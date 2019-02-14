import json
import logging
import os
import re
import shutil
import stat
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory

import libvirt

from libvmi import LibvmiError
from nitro.backends.backend import Backend
from nitro.backends.windows.arguments import WindowsArgumentMap
from nitro.backends.windows.process import WindowsProcess
from nitro.event import SyscallDirection
from nitro.syscall import Syscall

GETSYMBOLS_SCRIPT = 'get_symbols.py'


class WindowsBackend(Backend):
    __slots__ = (
        "nb_vcpu",
        "syscall_stack",
        "sdt",
        "tasks_offset",
        "pdbase_offset",
        "processes",
        "symbols"
    )

    def __init__(self, domain, libvmi, listener, syscall_filtering=True):
        super().__init__(domain, libvmi, listener, syscall_filtering)
        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        # create on syscall stack per vcpu
        self.syscall_stack = tuple([] for _ in range(self.nb_vcpu))
        self.sdt = None
        self.load_symbols()

        # get offsets
        self.tasks_offset = self.libvmi.get_offset("win_tasks")
        self.pdbase_offset = self.libvmi.get_offset("win_pdbase")

        self.processes = {}
        self.accepted_count = 1

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
        # load ssdt entries
        nt_ssdt = {'ServiceTable': {}, 'ArgumentTable': {}}
        win32k_ssdt = {'ServiceTable': {}, 'ArgumentTable': {}}
        self.sdt = [nt_ssdt, win32k_ssdt]
        cur_ssdt = None
        for e in symbols['syscall_table']:
            if isinstance(e, list) and e[0] == 'r':
                if e[1]["divider"] is not None:
                    # new table
                    m = re.match(r'Table ([0-9]) @ .*', e[1]["divider"])
                    idx = int(m.group(1))
                    cur_ssdt = self.sdt[idx]['ServiceTable']
                else:
                    entry = e[1]["entry"]
                    full_name = e[1]["symbol"]["symbol"]
                    # add entry  to our current ssdt
                    cur_ssdt[entry] = full_name
                    logging.debug('Add SSDT entry [%s] -> %s', entry, full_name)
        # save rekall symbols
        self.symbols = symbols

    def process_event(self, event):
        # invalidate libvmi cache
        self.libvmi.v2pcache_flush(0)
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()
        # rebuild context
        cr3 = event.sregs.cr3
        # 1 find process
        process = self.associate_process(cr3)
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

        args = WindowsArgumentMap(event, process)
        if name == 'Unknown':
            cleaned = 'Unknown'
        else:
            cleaned = clean_name(name) if name is not None else None
        syscall = Syscall(event, name, cleaned, process, args)
        # dispatch on the hooks
        self.dispatch_hooks(syscall)
        return syscall

    def define_hook(self, name, callback, direction=SyscallDirection.enter):
        super().define_hook(name, callback, direction)
        if self.syscall_filtering:
            self.add_syscall_filter(name)

    def undefine_hook(self, name, direction=SyscallDirection.enter):
        super().undefine_hook(name, direction)
        if self.syscall_filtering:
            self.remove_syscall_filter(name)

    def find_syscall_nb(self, syscall_name):
        for ssdt in self.sdt:
            for syscall_nb, full_name in ssdt['ServiceTable'].items():
                if re.match(r'^.*{}$'.format(syscall_name), full_name):
                    return syscall_nb
        return None

    def get_kernel_processes(self, ppid):
        self.libvmi.v2pcache_flush(0)
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()
        ps_head = self.libvmi.translate_ksym2v('PsActiveProcessHead')
        flink = self.libvmi.read_addr_ksym('PsActiveProcessHead')

        count = 0
        kernel_thread = set(())
        # Traverse every EProcess
        while flink != ps_head:
            # get start of EProcess
            start_eproc = flink - self.symbols['offsets']['EPROCESS'][
                'ActiveProcessLinks']
            # move to ThreadListEntry of KTHREADS
            kernel_thread_list_head = start_eproc + \
                                      self.symbols['offsets']['KPROCESS'][
                                          'ThreadListHead']
            # read KTHREADS.ThreadListEntry->Flink(offset 0x0)
            kthread_flink = self.libvmi.read_addr_va(
                kernel_thread_list_head, 0)
            while kthread_flink != kernel_thread_list_head:
                start_kthrd = kthread_flink - self.symbols['offsets']['KTHREAD']['ThreadListEntry']
                kthread_stack = self.libvmi.read_addr_va(start_kthrd + self.symbols['offsets']['KTHREAD']['KernelStack'], 0)
                ks_eip = self.libvmi.read_addr_va(kthread_stack + 2*8, 0)
                # ks_ebp = self.libvmi.read_addr_va(kthread_stack + 3*8, 0)

                if ks_eip >= 0xFFFF080000000000:
                    kthread_stats = self.libvmi.read_8_va(start_kthrd + self.symbols['offsets']['KTHREAD']['State'], 0)
                    # print(ppid, kprocess_id, kthread_id)

                    if kthread_stats in [1, 2]:
                        kprocess_id = self.libvmi.read_32_va(start_kthrd + self.symbols['offsets']['ETHREAD']['Cid'], 0)

                        kthread_id = self.libvmi.read_32_va(start_kthrd + self.symbols['offsets']['ETHREAD']['Cid'] +
                                                            self.symbols['offsets']['CLIENT_ID']['UniqueThread'], 0)
                        image_file_name_off = self.symbols['offsets']['EPROCESS']['ImageFileName']
                        image_file_name_addr = start_eproc + image_file_name_off
                        proc_name = self.libvmi.read_str_va(image_file_name_addr, 0)
                        print('thread: {}'.format(kthread_id))
                        yield kprocess_id, proc_name

                        print('ks: {}, eip: {}, state: {}, start_kthrd: {}, Cid: {}, Pid: {}'.format(hex(kthread_stack), hex(ks_eip), kthread_stats, hex(start_kthrd), kthread_id, kprocess_id))
                        kernel_thread.add('{}-{}'.format(kthread_id, kprocess_id))
                # read new flink
                kthread_flink = self.libvmi.read_addr_va(kthread_flink, 0)

            # read new flink
            flink = self.libvmi.read_addr_va(flink, 0)
        count = len(kernel_thread)
        print("Total number of processes in kernel mode: {}".format(count))
        return count

    def associate_process(self, cr3):
        if cr3 in self.processes:
            p = self.processes[cr3]
        else:
            p = self.find_eprocess(cr3)
            # index by cr3 or pid
            # a callback might want to search by pid
            self.processes[cr3] = p
            self.processes[p.pid] = p
        return p

    def find_eprocess(self, cr3):
        # read PsActiveProcessHead list_entry
        ps_head = self.libvmi.translate_ksym2v('PsActiveProcessHead')
        flink = self.libvmi.read_addr_ksym('PsActiveProcessHead')

        while flink != ps_head:
            # get start of EProcess
            start_eproc = flink - self.symbols['offsets']['EPROCESS'][
                'ActiveProcessLinks']
            # move to start of DirectoryTableBase
            directory_table_base_off = start_eproc + \
                                       self.symbols['offsets']['KPROCESS'][
                                           'DirectoryTableBase']
            # read directory_table_base
            directory_table_base = self.libvmi.read_addr_va(
                directory_table_base_off, 0)
            # compare to our cr3
            if cr3 == directory_table_base:
                return WindowsProcess(self.libvmi, cr3, start_eproc,
                                      self.symbols)
            # read new flink
            flink = self.libvmi.read_addr_va(flink, 0)
        raise RuntimeError('Process not found')

    def get_syscall_name(self, rax):
        ssn = rax & 0xFFF
        idx = (rax & 0x3000) >> 12
        try:
            syscall_name = self.sdt[idx]['ServiceTable'][ssn]
        except (KeyError, IndexError):
            # this code should not be reached,
            # because there is only 2 SSDT's defined in Windows (Nt and Win32k)
            # the 2 others are NULL
            syscall_name = 'Table{}!Unknown'.format(idx)
        return syscall_name

    def add_syscall_filter(self, syscall_name):
        syscall_nb = self.find_syscall_nb(syscall_name)
        if syscall_nb is None:
            raise RuntimeError(
                'Unable to find syscall number for %s' % syscall_name)
        self.listener.add_syscall_filter(syscall_nb)

    def remove_syscall_filter(self, syscall_name):
        syscall_nb = self.find_syscall_nb(syscall_name)
        if syscall_nb is None:
            raise RuntimeError(
                'Unable to find syscall number for %s' % syscall_name)
        self.listener.remove_syscall_filter(syscall_nb)


def clean_name(name):
    return name.split('!')[-1]
