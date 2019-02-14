#!/usr/bin/env python2

"""

Usage:
  symbols.py <ram_dump>

Options:
  -h --help     Show this screen.

"""

import os
import logging
import StringIO
import json
from collections import defaultdict

# logging.basicConfig(level=logging.DEBUG)


from docopt import docopt
from rekall import session
from rekall import plugins

def main(args):
    ram_dump = args['<ram_dump>']
    home = os.getenv('HOME')
    # we need to make sure the directory exists otherwise rekall will complain
    # when we specify it in the profile_path
    local_cache_path = os.path.join(home, '.rekall_cache')
    base_directory = os.path.dirname(os.path.realpath(__file__))
    try:
        os.makedirs(local_cache_path)
    except OSError:  # already exists
        pass

    s = session.Session()
    with s:
        s.SetParameter("filename", ram_dump)
        s.SetParameter("profile", "rekall-profiles/Ubuntu/4.4.0-87-generic")
    s.logging.setLevel(4)
    symbols = {}
    symbols['offsets'] = get_offsets(s)
    symbols['sizes'] = get_sizes(s)

    print(json.dumps(symbols))


def get_offsets(session):
    offsets = defaultdict(dict)

    # task_struct
    offsets['task_struct']['tasks'] = session.profile.get_obj_offset('task_struct', 'tasks')
    offsets['task_struct']['pid'] = session.profile.get_obj_offset('task_struct', 'pid')
    offsets['task_struct']['mm'] = session.profile.get_obj_offset('task_struct', 'mm')
    offsets['task_struct']['comm'] = session.profile.get_obj_offset('task_struct', 'comm')
    offsets['task_struct']['thread'] = session.profile.get_obj_offset('task_struct', 'thread')
    offsets['task_struct']['state'] = session.profile.get_obj_offset('task_struct', 'state')
    offsets['task_struct']['flags'] = session.profile.get_obj_offset('task_struct', 'flags')
    kcov = session.profile.get_obj_offset('task_struct', 'kcov')
    if kcov:
        offsets['task_struct']['kcov'] = kcov
        offsets['task_struct']['kcov_mode'] = session.profile.get_obj_offset('task_struct', 'kcov_mode')
        offsets['task_struct']['kcov_size'] = session.profile.get_obj_offset('task_struct', 'kcov_size')
        offsets['task_struct']['kcov_area'] = session.profile.get_obj_offset('task_struct', 'kcov_area')

    offsets['task_struct']['exit_code'] = session.profile.get_obj_offset('task_struct', 'exit_code')
    offsets['task_struct']['sysvsem'] = session.profile.get_obj_offset('task_struct', 'sysvsem')
    offsets['task_struct']['sysvshm'] = session.profile.get_obj_offset('task_struct', 'sysvshm')
    offsets['task_struct']['files'] = session.profile.get_obj_offset('task_struct', 'files')
    offsets['task_struct']['fs'] = session.profile.get_obj_offset('task_struct', 'fs')
    offsets['task_struct']['nsproxy'] = session.profile.get_obj_offset('task_struct', 'nsproxy')
    offsets['task_struct']['mempolicy'] = session.profile.get_obj_offset('task_struct', 'mempolicy')
    offsets['task_struct']['io_context'] = session.profile.get_obj_offset('task_struct', 'io_context')
    offsets['task_struct']['splice_pipe'] = session.profile.get_obj_offset('task_struct', 'splice_pipe')
    offsets['task_struct']['task_frag'] = session.profile.get_obj_offset('task_struct', 'task_frag')
    offsets['task_struct']['se'] = session.profile.get_obj_offset('task_struct', 'se')
    offsets['task_struct']['rt'] = session.profile.get_obj_offset('task_struct', 'rt')
    offsets['task_struct']['exit_state'] = session.profile.get_obj_offset('task_struct', 'exit_state')
    offsets['task_struct']['exit_signal'] = session.profile.get_obj_offset('task_struct', 'exit_signal')
    offsets['task_struct']['thread_group'] = session.profile.get_obj_offset('task_struct', 'thread_group')
    offsets['task_struct']['signal'] = session.profile.get_obj_offset('task_struct', 'signal')
    offsets['task_struct']['stack'] = session.profile.get_obj_offset('task_struct', 'stack')
    offsets['task_struct']['pending'] = session.profile.get_obj_offset('task_struct', 'pending')
    offsets['task_struct']['jobctl'] = session.profile.get_obj_offset('task_struct', 'jobctl')
    offsets['task_struct']['task_works'] = session.profile.get_obj_offset('task_struct', 'task_works')
    offsets['task_struct']['perf_event_list'] = session.profile.get_obj_offset('task_struct', 'perf_event_list')
    offsets['task_struct']['plug'] = session.profile.get_obj_offset('task_struct', 'plug')

    # mm_struct
    offsets['mm_struct']['pgd'] = session.profile.get_obj_offset('mm_struct', 'pgd')

    # thread_struct
    offsets['thread_struct']['sp'] = session.profile.get_obj_offset('thread_struct', 'sp')
    offsets['thread_struct']['io_bitmap_ptr'] = session.profile.get_obj_offset('thread_struct', 'io_bitmap_ptr')
    offsets['thread_struct']['io_bitmap_max'] = session.profile.get_obj_offset('thread_struct', 'io_bitmap_max')

    # sysv_sem
    offsets['sysv_sem']['undo_list'] = session.profile.get_obj_offset('sysv_sem', 'undo_list')

    # sysv_shm
    offsets['sysv_shm']['shm_clist'] = session.profile.get_obj_offset('sysv_shm', 'shm_clist')

    # page_frag
    offsets['page_frag']['page'] = session.profile.get_obj_offset('page_frag', 'page')

    # kcov
    if kcov:
        offsets['kcov']['t'] = session.profile.get_obj_offset('kcov', 't')

    # rq
    offsets['rq']['curr'] = 0x8b0
    offsets['rq']['nr_running'] = 0x4

    # sched_entity
    offsets['sched_entity']['parent'] = session.profile.get_obj_offset('sched_entity', 'parent')
    offsets['sched_entity']['cfs_rq'] = session.profile.get_obj_offset('sched_entity', 'cfs_rq')
    offsets['sched_entity']['run_node'] = session.profile.get_obj_offset('sched_entity', 'run_node')
    offsets['sched_entity']['on_rq'] = session.profile.get_obj_offset('sched_entity', 'on_rq')
    offsets['sched_entity']['load'] = session.profile.get_obj_offset('sched_entity', 'load')
    offsets['sched_entity']['vruntime'] = session.profile.get_obj_offset('sched_entity', 'vruntime')

    # sched_rt_entity
    # offsets['sched_rt_entity']['rt_rq'] = session.profile.get_obj_offset('sched_rt_entity', 'rt_rq')

    # cfs_rq
    offsets['cfs_rq']['last'] = 0x48
    offsets['cfs_rq']['next'] = 0x40
    offsets['cfs_rq']['skip'] = 0x50
    offsets['cfs_rq']['curr'] = 0x38
    offsets['cfs_rq']['h_nr_running'] = 0x14
    offsets['cfs_rq']['nr_running'] = 0x14
    offsets['cfs_rq']['rb_leftmost'] = 0x30
    offsets['cfs_rq']['tasks_timeline'] = 0x28
    offsets['cfs_rq']['load'] = 0x0
    offsets['cfs_rq']['rq'] = 0xc8
    offsets['cfs_rq']['min_vruntime'] = 0x20
    offsets['cfs_rq']['throttled'] = 0x120

    # rb_node
    offsets['rb_node']['__rb_parent_color'] = session.profile.get_obj_offset('rb_node', '__rb_parent_color')
    offsets['rb_node']['rb_right'] = session.profile.get_obj_offset('rb_node', 'rb_right')
    offsets['rb_node']['rb_left'] = session.profile.get_obj_offset('rb_node', 'rb_left')

    # rb_root
    offsets['rb_root']['rb_node'] = session.profile.get_obj_offset('rb_root', 'rb_node')

    # load_weight
    offsets['load_weight']['weight'] = session.profile.get_obj_offset('load_weight', 'weight')
    offsets['load_weight']['inv_weight'] = session.profile.get_obj_offset('load_weight', 'inv_weight')

    # signal_struct
    offsets['signal_struct']['shared_pending'] = session.profile.get_obj_offset('signal_struct', 'shared_pending')
    offsets['signal_struct']['flags'] = session.profile.get_obj_offset('signal_struct', 'flags')
    offsets['signal_struct']['group_exit_code'] = session.profile.get_obj_offset('signal_struct', 'group_exit_code')
    offsets['signal_struct']['group_stop_count'] = session.profile.get_obj_offset('signal_struct', 'group_stop_count')

    # sigpending
    offsets['sigpending']['signal'] = session.profile.get_obj_offset('sigpending', 'signal')

    # thread_info
    offsets['thread_info']['flags'] = 0x8

    return offsets


def get_sizes(session):
    sizes = defaultdict(dict)

    # task_struct
    sizes['list_head'] = session.profile.get_obj_size('list_head')
    # sizes['pid_t'] = session.profile.get_obj_size('pid_t')
    sizes['mm_struct'] = session.profile.get_obj_size('mm_struct')
    sizes['thread_struct'] = session.profile.get_obj_size('thread_struct')
    sizes['unsigned_int'] = session.profile.get_obj_size('unsigned int')
    sizes['int'] = session.profile.get_obj_size('int')
    # sizes['task_struct']['flags'] = session.profile.get_obj_size('task_struct', 'flags')
    sizes['pt_regs'] = session.profile.get_obj_size('pt_regs')
    sizes['rq']['curr'] = 8
    # kcov = session.profile.get_obj_size('task_struct', 'kcov')
    # if kcov:
    #     sizes['task_struct']['kcov'] = kcov
    #     sizes['task_struct']['kcov_mode'] = session.profile.get_obj_size('task_struct', 'kcov_mode')
    #     sizes['task_struct']['kcov_size'] = session.profile.get_obj_size('task_struct', 'kcov_size')
    #     sizes['task_struct']['kcov_area'] = session.profile.get_obj_size('task_struct', 'kcov_area')
    #
    # sizes['task_struct']['exit_code'] = session.profile.get_obj_size('task_struct', 'exit_code')
    # sizes['task_struct']['sysvsem'] = session.profile.get_obj_size('task_struct', 'sysvsem')
    # sizes['task_struct']['sysvshm'] = session.profile.get_obj_size('task_struct', 'sysvshm')
    # sizes['task_struct']['files'] = session.profile.get_obj_size('task_struct', 'files')
    # sizes['task_struct']['fs'] = session.profile.get_obj_size('task_struct', 'fs')
    # sizes['task_struct']['nsproxy'] = session.profile.get_obj_size('task_struct', 'nsproxy')
    # sizes['task_struct']['mempolicy'] = session.profile.get_obj_size('task_struct', 'mempolicy')
    # sizes['task_struct']['io_context'] = session.profile.get_obj_size('task_struct', 'io_context')
    # sizes['task_struct']['splice_pipe'] = session.profile.get_obj_size('task_struct', 'splice_pipe')
    # sizes['task_struct']['task_frag'] = session.profile.get_obj_size('task_struct', 'task_frag')
    #
    # # mm_struct
    # sizes['mm_struct']['pgd'] = session.profile.get_obj_size('mm_struct', 'pgd')
    #
    # # thread_struct
    # sizes['thread_struct']['sp'] = session.profile.get_obj_size('thread_struct', 'sp')
    # sizes['thread_struct']['io_bitmap_ptr'] = session.profile.get_obj_size('thread_struct', 'io_bitmap_ptr')
    # sizes['thread_struct']['io_bitmap_max'] = session.profile.get_obj_size('thread_struct', 'io_bitmap_max')
    #
    # # sysv_sem
    # sizes['sysv_sem']['undo_list'] = session.profile.get_obj_size('sysv_sem', 'undo_list')
    #
    # # sysv_shm
    # sizes['sysv_shm']['shm_clist'] = session.profile.get_obj_size('sysv_shm', 'shm_clist')
    #
    # # page_frag
    # sizes['page_frag']['page'] = session.profile.get_obj_size('page_frag', 'page')
    #
    # # kcov
    # if kcov:
    #     sizes['kcov']['t'] = session.profile.get_obj_size('kcov', 't')

    return sizes


if __name__ == '__main__':
    main(docopt(__doc__))
