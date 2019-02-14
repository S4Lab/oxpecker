import logging
import re

from ctypes import sizeof, c_void_p

from nitro.syscall import Syscall
from nitro.event import SyscallDirection
from libvmi import LibvmiError
from nitro.backends.freebsd.process import FreeBSDProcess
from nitro.backends.backend import Backend
from nitro.backends.freebsd.arguments import FreeBSDArgumentMap

# Technically, I do not think using this the way
#  I do is correct since it might be different for the VM
VOID_P_SIZE = sizeof(c_void_p)

HANDLER_NAME_REGEX = re.compile(r"^(SyS|sys)_(?P<name>.+)")

class FreeBSDBackend(Backend):
    __slots__ = (
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

        self.tasks_offset = self.libvmi.get_offset("freebsd_tasks")
        self.pid_offset = self.libvmi.get_offset("freebsd_pid")
        self.mm_offset = self.libvmi.get_offset("freebsd_mm")
        self.pgd_offset = self.libvmi.get_offset("freebsd_pgd")
        self.name_offset = self.libvmi.get_offset("freebsd_name")
        self.thread_offset = 0x9c0
        self.sp_offset = 0x20
        self.state_offset = 0x0
        self.flags_offset = 0x14
        self.ip_offset = 0x448
        self.size_of_regs = 168
        self.PF_KTHREAD = 0x200000

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
        if event.direction == SyscallDirection.exit:
            try:
                syscall = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                syscall = Syscall(event, "Unknown", "Unknown", process, None)
        else:
            try:
                name = self.get_syscall_name(event.regs.rax)
                args = FreeBSDArgumentMap(event, process)
                cleaned = clean_name(name) if name is not None else None
                syscall = Syscall(event, name, cleaned, process, args)
            except LibvmiError as error:
                logging.error("FreeBSDBackend: failed to get_syscall_name (LibvmiError)")
                raise error
            self.syscall_stack[event.vcpu_nb].append(syscall)
        self.dispatch_hooks(syscall)
        return syscall

    def get_syscall_name(self, rax):
        # address of the pointer within the sys_call_table array
        p_addr = self.sys_call_table_addr + (rax * VOID_P_SIZE)
        # get the address of the procedure
        addr = self.libvmi.read_addr_va(p_addr, 0)
        # translate the address into a name
        return self.libvmi.translate_v2ksym(addr)

    def get_kernel_processes(self, ppid):
        self.libvmi.v2pcache_flush(0)
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()

        head = self.libvmi.translate_ksym2v("init_task")
        next_ = head
        # next_ = self.libvmi.read_addr_va(next_ + self.cfs_rq_offset, 0) - self.tasks_offset
        count = 0

        while True:  # Maybe this should have a sanity check stopping it
            print_process = False
            state = self.libvmi.read_64_va(next_ + self.state_offset, 0)
            if state == 0:
                flags = self.libvmi.read_32_va(next_ + self.flags_offset, 0)
                if flags & self.PF_KTHREAD:
                    stack_pointer = self.libvmi.read_addr_va(next_ + self.thread_offset + self.sp_offset, 0)

                    regs = stack_pointer - self.size_of_regs
                    ip = self.libvmi.read_32_va(regs + self.ip_offset, 0)
                    print("ip is {}".format(ip))
                    print_process = True

                else:
                    stack_pointer = self.libvmi.read_addr_va(next_ + self.thread_offset + self.sp_offset, 0)

                    regs = stack_pointer - self.size_of_regs
                    ip = self.libvmi.read_32_va(regs + self.ip_offset, 0)
                    if ip != 0:
                        print("ip is {}".format(ip))
                        print_process = True
            if print_process:
                pid = self.libvmi.read_32_va(next_ + self.pid_offset, 0)
                if ppid != pid:
                    count += 1
                procname = self.libvmi.read_str_va(next_ + self.name_offset, 0)
                yield pid, procname

            next_ = self.libvmi.read_addr_va(next_ + self.tasks_offset, 0) - self.tasks_offset
            if next_ == head:
                break
        print("Total number of processes in kernel mode: {}".format(count))
        return count

    def associate_process(self, cr3):
        """Get Process associated with CR3"""
        head = self.libvmi.translate_ksym2v("init_task") # get the address of swapper's task_struct
        next_ = head
        while True: # Maybe this should have a sanity check stopping it
            mm = self.libvmi.read_addr_va(next_ + self.mm_offset, 0)
            if not mm:
                mm = self.libvmi.read_addr_va(next_ + self.mm_offset + VOID_P_SIZE, 0)
            if mm:
                pgd = self.libvmi.read_addr_va(mm + self.pgd_offset, 0)
                pgd_phys_addr = self.libvmi.translate_kv2p(pgd)
                if cr3 == pgd_phys_addr:
                    # Eventually, I would like to look for the executable name from mm->exe_file->f_path
                    return FreeBSDProcess(self.libvmi, cr3, next_)
            else:
                #logging.debug("missing mm")
                pass
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
