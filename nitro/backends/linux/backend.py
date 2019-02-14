import json
import logging
import os
import re
import shutil
import stat
import subprocess
from ctypes import sizeof, c_void_p
from tempfile import NamedTemporaryFile, TemporaryDirectory

import libvirt
from libvmi import LibvmiError, AccessContext, TranslateMechanism

from nitro.backends.backend import Backend
from nitro.backends.linux.arguments import LinuxArgumentMap
from nitro.backends.linux.process import LinuxProcess
from nitro.event import SyscallDirection
from nitro.syscall import Syscall

# Technically, I do not think using this the way
#  I do is correct since it might be different for the VM
VOID_P_SIZE = sizeof(c_void_p)

HANDLER_NAME_REGEX = re.compile(r"^(SyS|sys)_(?P<name>.+)")

GETSYMBOLS_SCRIPT = 'get_symbols.py'


class LinuxBackend(Backend):
    __slots__ = (
        "symbols",
        "sys_call_table_addr",
        "nb_vcpu",
        "syscall_stack",
        "tasks_offset",
        "pid_offset",
        "mm_offset",
        "pgd_offset",
        "name_offset",
        "thread_offset",
        "sp_offset",
        "state_offset",
        "flags_offset",
        "ip_offset",
        "size_of_regs",
        "PF_KTHREAD"
    )

    def __init__(self, domain, libvmi, listener, syscall_filtering=True):
        super().__init__(domain, libvmi, listener, syscall_filtering)
        self.sys_call_table_addr = self.libvmi.translate_ksym2v("sys_call_table")
        logging.debug("sys_call_table at %s", hex(self.sys_call_table_addr))

        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        self.syscall_stack = tuple([] for _ in range(self.nb_vcpu))

        self.load_symbols()

        self.tasks_offset = self.symbols['offsets']['task_struct']['tasks']
        self.pid_offset = self.symbols['offsets']['task_struct']['pid']
        self.mm_offset = self.symbols['offsets']['task_struct']['mm']
        self.pgd_offset = self.symbols['offsets']['mm_struct']['pgd']
        self.name_offset = self.symbols['offsets']['task_struct']['comm']
        self.thread_offset = self.symbols['offsets']['task_struct']['thread']
        self.sp_offset = self.symbols['offsets']['thread_struct']['sp']
        self.state_offset = self.symbols['offsets']['task_struct']['state']
        self.flags_offset = self.symbols['offsets']['task_struct']['flags']
        self.ip_offset = self.pid_offset
        self.size_of_regs = 168
        self.PF_KTHREAD = 0x200000
        self.accepted_count = 0

    def load_symbols(self):
        # we need to put the ram dump in our own directory
        # because otherwise it will be created in /tmp
        # and later owned by root
        with TemporaryDirectory() as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir) as ram_dump:
                # chmod to be r/w by everyone
                os.chmod(ram_dump.name,
                         stat.S_IRUSR | stat.S_IWUSR |
                         stat.S_IRGRP | stat.S_IWGRP |
                         stat.S_IROTH | stat.S_IWOTH)
                # take a ram dump
                logging.info('Dumping physical memory to %s', ram_dump.name)
                flags = libvirt.VIR_DUMP_MEMORY_ONLY
                dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
                self.domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
                # build symbols.py absolute path
                script_dir = os.path.dirname(os.path.realpath(__file__))
                symbols_script_path = os.path.join(script_dir,
                                                   GETSYMBOLS_SCRIPT)
                # call rekall on ram dump
                logging.info('Extracting symbols with Rekall')
                python2 = shutil.which('python2')
                symbols_process = [python2, symbols_script_path, ram_dump.name]
                output = subprocess.check_output(symbols_process)
        logging.info('Loading symbols')
        # load output as json
        symbols = json.loads(output.decode('utf-8'))
        print(symbols)
        # save rekall symbols
        self.symbols = symbols

    def process_event(self, event):
        # Clearing these caches is really important since otherwise we will end
        # up with incorrect memory references. Unfortunatelly, this will also
        # make the backend slow. In my limited testing it seems that only
        # clearing v2p cache works most of the time but I am sure issues will
        # arise.
        self.libvmi.v2pcache_flush(0)
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()

        process = self.associate_process(event.sregs.cr3)
        # 2 find syscall
        try:
            if event.direction == SyscallDirection.exit:
                try:
                    name = self.syscall_stack[event.vcpu_nb].pop()
                except IndexError:
                    name = 'Unknown'
            else:
                name = self.get_syscall_name(event.regs.rax)
                # push them to the stack
                self.syscall_stack[event.vcpu_nb].append(name)
        except LibvmiError as error:
            logging.error("LinuxBackend: failed to get_syscall_name (LibvmiError)")
            raise error

        args = LinuxArgumentMap(event, process)
        if name == 'Unknown':
            cleaned = 'Unknown'
        else:
            cleaned = clean_name(name) if name is not None else None
        syscall = Syscall(event, name, cleaned, process, args)

        self.dispatch_hooks(syscall)
        return syscall

    def get_syscall_name(self, rax):
        # address of the pointer within the sys_call_table array
        p_addr = self.sys_call_table_addr + (rax * VOID_P_SIZE)
        # get the address of the procedure
        addr = self.libvmi.read_addr_va(p_addr, 0)
        # translate the address into a name
        ctx = AccessContext(TranslateMechanism.PROCESS_PID)
        return self.libvmi.translate_v2ksym(ctx, addr)

    def get_kernel_processes(self, ppid):
        self.libvmi.v2pcache_flush(0)
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()

        head = self.libvmi.translate_ksym2v("init_task")
        next_ = self.libvmi.read_addr_va(head + self.tasks_offset, 0) - self.tasks_offset
        count = 0
        kernel_thread = set(())
        while True:  # Maybe this should have a sanity check stopping it
            print_process = False
            state = self.libvmi.read_64_va(next_ + self.state_offset, 0)
            if state == 0:
                flags = self.libvmi.read_32_va(next_ + self.flags_offset, 0)
                if flags & self.PF_KTHREAD:
                    stack_pointer = self.libvmi.read_addr_va(next_ + self.thread_offset + self.sp_offset, 0)

                    regs = stack_pointer - self.size_of_regs
                    ip = self.libvmi.read_32_va(regs + self.ip_offset, 0)
                    # print("ip is {}".format(ip))
                    print_process = True

                else:
                    stack_pointer = self.libvmi.read_addr_va(next_ + self.thread_offset + self.sp_offset, 0)

                    regs = stack_pointer - self.size_of_regs
                    ip = self.libvmi.read_32_va(regs + self.ip_offset, 0)
                    if ip != 0:
                        # print("ip is {}".format(ip))
                        print_process = True
            if print_process:
                pid = self.libvmi.read_32_va(next_ + self.pid_offset, 0)
                if ppid != pid:
                    kernel_thread.add('{}'.format(pid))
                procname = self.libvmi.read_str_va(next_ + self.name_offset, 0)
                yield pid, procname

            next_ = self.libvmi.read_addr_va(next_ + self.tasks_offset, 0) - self.tasks_offset
            if next_ == head:
                break
        count = len(kernel_thread)
        print("Total number of processes in kernel mode: {}".format(count))
        return count

    def associate_process(self, cr3):
        """Get Process associated with CR3"""
        head = self.libvmi.translate_ksym2v("init_task")  # get the address of swapper's task_struct
        next_ = head
        while True:  # Maybe this should have a sanity check stopping it
            mm = self.libvmi.read_addr_va(next_ + self.mm_offset, 0)
            if not mm:
                mm = self.libvmi.read_addr_va(next_ + self.mm_offset + VOID_P_SIZE, 0)
            if mm:
                pgd = self.libvmi.read_addr_va(mm + self.pgd_offset, 0)
                pgd_phys_addr = self.libvmi.translate_kv2p(pgd)
                if cr3 == pgd_phys_addr:
                    # Eventually, I would like to look for the executable name from mm->exe_file->f_path
                    return LinuxProcess(self.libvmi, cr3, next_)
            else:
                logging.debug("missing mm")
                pass
            next_ = self.libvmi.read_addr_va(next_ + self.tasks_offset, 0) - self.tasks_offset
            if next_ == head:
                break

    def runqueues_curr(self):
        rq_ = self.libvmi.translate_ksym2v("runqueues")
        print(hex(rq_), hex(rq_ + self.symbols['offsets']['rq']['curr']))
        curr_ = self.libvmi.read_64_va(rq_ + self.symbols['offsets']['rq']['curr'], 0)
        print(curr_)
        _pid = self.libvmi.read_32_va(curr_ + self.symbols['offsets']['task_struct']['pid'], 0)
        print("Current pid is:", _pid)

    def get_process(self, pid):
        """Get Process associated with CR3"""
        head = self.libvmi.translate_ksym2v("init_task")  # get the address of swapper's task_struct
        next_ = head
        while True:  # Maybe this should have a sanity check stopping it
            _pid = self.libvmi.read_32_va(next_ + self.pid_offset, 0)
            if _pid == pid:
                mm = self.libvmi.read_addr_va(next_ + self.mm_offset, 0)
                if not mm:
                    mm = self.libvmi.read_addr_va(next_ + self.mm_offset + VOID_P_SIZE, 0)
                if mm:
                    pgd = self.libvmi.read_addr_va(mm + self.pgd_offset, 0)
                    cr3 = self.libvmi.translate_kv2p(pgd)
                    return LinuxProcess(self.libvmi, cr3, next_)
                else:
                    # logging.debug("missing mm")
                    return LinuxProcess(self.libvmi, None, next_)
            next_ = self.libvmi.read_addr_va(next_ + self.tasks_offset, 0) - self.tasks_offset
            if next_ == head:
                break

    def define_hook(self, name, callback, direction=SyscallDirection.enter):
        super().define_hook(name, callback, direction)
        if self.syscall_filtering:
            self.add_syscall_filter(name)

    def undefine_hook(self, name, direction=SyscallDirection.enter):
        super().undefine_hook(name, direction)
        if self.syscall_filtering:
            self.remove_syscall_filter(name)

    def add_syscall_filter(self, syscall_name):
        raise RuntimeError('Unimplemented feature')

    def remove_syscall_filter(self, syscall_name):
        raise RuntimeError('Unimplemented feature')


def clean_name(name):
    matches = HANDLER_NAME_REGEX.search(name)
    return matches.group("name") if matches is not None else name
