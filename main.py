#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro [options] <vm_name>

Options:
  -h --help            Show this screen
  --nobackend          Don't analyze events
  -o FILE --out=FILE   Output file (stdout if not specified)

"""
import csv
import logging
import random
import signal
import traceback
from time import sleep
from timeit import default_timer as timer

import libvirt
from docopt import docopt

from nitro.nitro import Nitro
from oxpecker.kill import Kill
from oxpecker.ox import OX


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


times = []


class Callback:
    def __init__(self, ox):
        self.ox = ox

    def do_callback(self):
        raise Exception("Does not support do_callback in parent")


class NOPCallback(Callback):
    def __init__(self, ox):
        super(NOPCallback, self).__init__(ox)

    def do_callback(self):
        pass


class KillCallback(Callback):
    def __init__(self, ox, pid):
        super(KillCallback, self).__init__(ox)
        self.pid = pid

    def do_callback(self):
        print("Killing process with pid {}".format(self.pid))
        kill = Kill(self.ox)
        kill.do_exit(self.pid)


class WriteCallback(Callback):
    def __init__(self, ox, vaddr, value=None):
        super(WriteCallback, self).__init__(ox)
        self.vaddr = vaddr
        self.value = value

    def do_callback(self):
        print("read here!")
        print(self.ox.ox_read_32_va(self.vaddr, 0))
        print("write here!")
        self.ox.ox_write_32_va(self.vaddr, 0, self.value if self.value else random.randint(0, 29))
        print("read here!")
        print(self.ox.ox_read_32_va(self.vaddr, 0))


class NitroRunner:
    def __init__(self, vm_name, analyze_enabled, output=None):
        self.start = timer()
        self.end = 0
        self.is_busy = False
        self.vm_name = vm_name
        self.analyze_enabled = analyze_enabled
        self.output = output
        # get domain from libvirt
        con = libvirt.open('qemu:///system')
        self.domain = con.lookupByName(vm_name)
        self.events = []
        self.nitro = None
        self.ox = None
        # define new SIGINT handler, to stop nitro
        signal.signal(signal.SIGINT, self.sigint_handler)

    def run(self):
        # ffff880074c13c74
        print("Wait for setup rekall and nitro ...")
        self.nitro = Nitro(self.domain, self.analyze_enabled)
        self.ox = OX(self.nitro)
        while True:
            print("Which program you want to execute:")
            print("---- help:")
            print("---- kill [pid]")
            print("---- write [vaddr] [optional value]")
            print("---- nop")
            print("---- exit")
            print("---- statistics")

            callback = None
            is_statistics = False

            cmd = input("> ")
            command = cmd.split()

            print(command)
            if command[0].lower() not in ["kill", "write", "exit", "nop", "statistics"]:
                print("Program not found")
                continue

            if command[0].lower() == "exit":
                print("Bye!")
                break
            try:
                if command[0].lower() == "statistics":
                    is_statistics = True
                if command[0].lower() == "nop":
                    callback = NOPCallback(self.ox).do_callback

                if command[0].lower() == "kill":
                    if len(command) != 2:
                        print("PID is needed for kill program")
                        continue
                    else:
                        callback = KillCallback(self.ox, int(command[1])).do_callback

                if command[0].lower() == "write":
                    if len(command) == 2:
                        callback = WriteCallback(self.ox, int(command[1], 0)).do_callback
                    elif len(command) == 3:
                        callback = WriteCallback(self.ox, int(command[1], 0), int(command[2])).do_callback
                    else:
                        print("vaddr is needed for write program")
                        continue

                loop_nr = int(input("> How many times do you want to execute this program[defualt: 1]: ") or "1")
                sleep_time = float(input("> How much do you want to sleep between each run[defualt: 0.1]: ") or "0.1")
                delay_file_output = input("> Save results in which file: ")

            except ValueError as e:
                print(e)
                print("Value error. Please enter a valid value")
                continue
            self.is_busy = 0
            busy_times = 0.0
            total_times = 0.0

            # callback()
            for i in range(0, loop_nr):
                print("#{}".format(i))
                # self.start = timer()
                try:
                    #     loop = asyncio.get_event_loop()
                    #     self.end = loop.run_until_complete(asyncio.wait_for(
                    #         self.ox.begin_transaction(callback, loop), 3)
                    #     )
                    #     for signame in ('SIGINT', 'SIGTERM'):
                    #         loop.add_signal_handler(getattr(signal, signame),
                    #                                 functools.partial(self.ox.run_rollback))
                    #
                    #     loop.close()
                    if is_statistics:
                        self.is_busy = self.ox.get_statistic()
                        self.end = 1
                        if self.is_busy:
                            busy_times += 1
                        total_times += 1
                    else:
                        self.end, self.start = self.ox.sync_begin_transaction(callback)
                except Exception as e:
                    traceback.print_exc()
                    print("Oxpecker got exception.")
                    self.end = 0
                    self.is_busy = 0
                finally:
                    if self.nitro.listener.current_cont_event:
                        self.nitro.listener.stop_listen()
                # self.is_busy = self.ox.get_statistic()
                # self.nitro.listener.stop()
                is_write_to_output = self.end != 0
                if delay_file_output and is_write_to_output:
                    row = [self.is_busy] if is_statistics else [self.start, self.end, self.end - self.start]
                    with open(delay_file_output, "a") as f:
                        writer = csv.writer(f)
                        writer.writerow(row)
                sleep(sleep_time)
            if is_statistics:
                print('busy times: {}, total_times:{}'.format(busy_times, total_times))
                print('The percentage of idle time: {}'.format(1.0 - busy_times/total_times))

        self.nitro.listener.close_fd()

    def sigint_handler(self, *args, **kwargs):
        logging.info('CTRL+C received, stopping Nitro')
        self.nitro.stop()


def main():
    init_logger()
    args = docopt(__doc__)
    vm_name = args['<vm_name>']
    analyze_enabled = False if args['--nobackend'] else True
    output = args['--out']
    runner = NitroRunner(vm_name, analyze_enabled, output)
    # for i in range(0, 3):
    runner.run()
    # if runner.end != 0:
    #     with open("test.csv", "a") as f:
    #         writer = csv.writer(f)
    #         writer.writerow([runner.start, runner.end, runner.end - runner.start])
    # with open("windows_kernel_statistic_10_load.csv", "a") as f:
    #     writer = csv.writer(f)
    #     writer.writerow([runner.is_busy])


if __name__ == '__main__':
    main()
