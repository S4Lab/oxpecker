import os
import signal
import traceback
from pprint import pprint
from threading import Lock
from time import sleep
from timeit import default_timer as timer

from libvmi import LibvmiError

from nitro.event import SyscallDirection


class OX:
    __slots__ = (
        "nitro",
        "analyze_enabled",
        "count",
        "rollback",
        "cancel",
    )

    def __init__(self, nitro):
        self.nitro = nitro
        self.analyze_enabled = self.nitro.introspection
        self.count = 0
        self.rollback = dict()

    def ox_count_of_kernel_process(self, pid):
        count = yield from self.nitro.backend.get_kernel_processes(pid)
        self.count = count

    def get_statistic(self):
        self.nitro.listener.set_traps(True)
        for event, continue_event in self.nitro.listen():
            event_info = event.as_dict()
            if self.analyze_enabled:
                try:
                    syscall = self.nitro.backend.process_event(event)
                except LibvmiError as e:
                    print(e)
                    # exc_traceback = sys.exc_info()
                    # print("*** print_tb:")
                    # traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
                    print("Backend event processing failure")
                    continue_event.set()
                    return 0
                else:
                    if event.direction == SyscallDirection.exit:
                        event_info = syscall.as_dict()
                        try:
                            if event_info.get('process'):
                                for pid, procname in self.ox_count_of_kernel_process(event_info['process']['pid']):
                                    # pass
                                    print("[%5d] %s" % (pid, procname))
                            else:
                                self.ox_count_of_kernel_process(-1)
                        except LibvmiError as e:
                            print(e)
                            # exc_traceback = sys.exc_info()
                            # print("*** print_tb:")
                            # traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
                            print("Backend event processing failure")
                            continue_event.set()
                            return 0
                        else:
                            if self.count <= self.nitro.backend.accepted_count:
                                continue_event.set()
                                return False
                            else:
                                continue_event.set()
                                return True
            continue_event.set()

    def sync_begin_transaction(self, callback):
        start = None
        self.nitro.listener.set_traps(True)
        count_of_try = 0
        for event, continue_event in self.nitro.listen():
            if not start:
                start = timer()
            if count_of_try >= 20:
                print("Maybe next time!")
                continue_event.set()
                return 0, 0
            # self.nitro.backend.domain.suspend()
            event_info = event.as_dict()
            if self.analyze_enabled:
                try:
                    syscall = self.nitro.backend.process_event(event)
                except LibvmiError as e:
                    print(e)
                    # exc_traceback = sys.exc_info()
                    # print("*** print_tb:")
                    traceback.print_exc()
                    print("Backend process event failure")
                    continue_event.set()
                    continue
                else:
                    if event.direction == SyscallDirection.exit:
                        count_of_try += 1
                        event_info = syscall.as_dict()
                        # pprint(event_info, width=1)
                        try:
                            if event_info.get('process'):
                                for pid, procname in self.ox_count_of_kernel_process(event_info['process']['pid']):
                                    # pass
                                    print("[%5d] %s" % (pid, procname))
                            else:
                                self.ox_count_of_kernel_process(-1)
                        except LibvmiError as e:
                            print(e)
                            # exc_traceback = sys.exc_info()
                            # print("*** print_tb:")
                            # traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
                            traceback.print_exc()
                            print("Counting kernel process failure")
                            continue
                        else:
                            if self.count <= self.nitro.backend.accepted_count:
                                end = timer()
                                callback_lock = Lock()
                                with callback_lock:
                                    # try:
                                    callback()
                                    # except Exception as e:
                                    #     print(e)
                                    #     self.run_rollback()
                                print("Resume VM vmi begin end!")
                                # self.nitro.backend.resume()
                                continue_event.set()
                                return end, start
                                # print("Resume VM vmi begin")
                                # self.nitro.backend.resume()
                                # self.nitro.listener.continue_all_vm()
                                # stop properly by CTRL+C
            continue_event.set()
            # self.nitro.listener.set_traps(False)
            # sleep(0.1)
            # self.nitro.listener.set_traps(True)

    async def begin_transaction(self, callback, loop):
        return await loop.run_in_executor(None, self.sync_begin_transaction, callback)

    @staticmethod
    def cancel_transaction():
        os.kill(os.getpid(), signal.SIGINT)

    def ox_commit(self):
        if self.rollback:
            self.rollback = dict()
        print("Resume VM commit")

        self.nitro.stop_listen()
        # self.nitro.backend.resume()

    def ox_write_va(self, vaddr, pid, buffer, atomic=False):
        if atomic:
            if vaddr not in self.rollback:
                res = self.ox_read_va(vaddr, pid, len(buffer))
                self.rollback[vaddr] = ['t_vmi_write_va', [vaddr, pid, res[1], res[0]]]
        self.nitro.backend.libvmi.write_va(vaddr, pid, buffer)

    def ox_write_32_va(self, vaddr, pid, value, atomic=False):
        if atomic:
            if vaddr not in self.rollback:
                self.rollback[vaddr] = ['t_vmi_write_32_va', [vaddr, pid, self.ox_read_32_va(vaddr, pid)]]
        self.nitro.backend.libvmi.write_32_va(vaddr, pid, value)

    def ox_write_64_va(self, vaddr, pid, value, atomic=False):
        if atomic:
            if vaddr not in self.rollback:
                self.rollback[vaddr] = ['t_vmi_write_64_va', [vaddr, pid, self.ox_read_64_va(vaddr, pid)]]
        self.nitro.backend.libvmi.write_64_va(vaddr, pid, value)

    def ox_write_addr_va(self, vaddr, pid, value, atomic=False):
        if atomic:
            if vaddr not in self.rollback:
                self.rollback[vaddr] = ['t_vmi_write_addr_va', [vaddr, pid, self.ox_read_addr_va(vaddr, pid)]]
        self.nitro.backend.libvmi.write_addr_va(vaddr, pid, value)

    def ox_read_va(self, vaddr, pid, count):
        return self.nitro.backend.libvmi.read_va(vaddr, pid, count)

    def ox_read_32_va(self, vaddr, pid):
        return self.nitro.backend.libvmi.read_32_va(vaddr, pid)

    def ox_read_64_va(self, vaddr, pid):
        return self.nitro.backend.libvmi.read_64_va(vaddr, pid)

    def ox_read_addr_va(self, vaddr, pid):
        return self.nitro.backend.libvmi.read_addr_va(vaddr, pid)

    def run_rollback(self):
        while len(self.rollback) > 0:
            vaddr, data = self.rollback.popitem()
            getattr(self.nitro.backend.libvmi, data[0])(*data[1])
