PF_EXITING = 0x00000004
PF_EXITPIDONE = 0x00000008
PF_NOFREEZE = 0x00008000

EXIT_DEAD = 16
EXIT_ZOMBIE = 32

SIGKILL = 9
SIGCHLD = 17

SIGNAL_GROUP_EXIT = 0x00000004

JOBCTL_STOP_DEQUEUED_BIT = 16  # /* stop signal dequeued */
JOBCTL_STOP_PENDING_BIT = 17  # /* task should stop for group stop */
JOBCTL_STOP_CONSUME_BIT = 18  # /* consume group stop count */
JOBCTL_TRAP_STOP_BIT = 19  # /* trap for STOP */
JOBCTL_TRAP_NOTIFY_BIT = 20  # /* trap for NOTIFY */
JOBCTL_TRAPPING_BIT = 21  # /* switching to TRACED */
JOBCTL_LISTENING_BIT = 22  # /* ptracer is listening for events */

JOBCTL_STOP_DEQUEUED = (1 << JOBCTL_STOP_DEQUEUED_BIT)
JOBCTL_STOP_PENDING = (1 << JOBCTL_STOP_PENDING_BIT)
JOBCTL_STOP_CONSUME = (1 << JOBCTL_STOP_CONSUME_BIT)
JOBCTL_TRAP_STOP = (1 << JOBCTL_TRAP_STOP_BIT)
JOBCTL_TRAP_NOTIFY = (1 << JOBCTL_TRAP_NOTIFY_BIT)
JOBCTL_TRAPPING = (1 << JOBCTL_TRAPPING_BIT)
JOBCTL_LISTENING = (1 << JOBCTL_LISTENING_BIT)

JOBCTL_TRAP_MASK = (JOBCTL_TRAP_STOP | JOBCTL_TRAP_NOTIFY)
JOBCTL_PENDING_MASK = (JOBCTL_STOP_PENDING | JOBCTL_TRAP_MASK)

TASK_RUNNING = 0
TASK_WAKEKILL = 128

TIF_SIGPENDING = 2
TIF_NEED_RESCHED = 3


class Kill:
    __slots__ = (
        "ox"
    )

    def __init__(self, ox):
        self.ox = ox

    def kcov_task_exit(self, tsk):
        if self.ox.nitro.backend.symbols['offsets']['task_struct'].get('kcov'):
            pass
        # t->kcov_mode = KCOV_MODE_DISABLED;

        # t->kcov_size = 0;
        # t->kcov_area = NULL;
        # t->kcov = NULL;
        # kcov->t = NULL;
        pass

    def find_rq_curr(self):
        rq_ = self.ox.nitro.libvmi.translate_ksym2v("runqueues")
        curr_ = self.ox.nitro.libvmi.read_addr_va(rq_ + self.ox.nitro.backend.symbols['offsets']['rq']['curr'], 0)
        _pid = self.ox.nitro.libvmi.read_32_va(curr_ + self.ox.nitro.backend.symbols['offsets']['task_struct']['pid'],
                                               0)
        print(_pid)

    def rb_next(self, node):
        # if (RB_EMPTY_NODE(node)) return NULL;
        if self.get_rb_pc(node) == node:
            return None
        node_rb_right = self.get_rb_right(node)
        if node_rb_right:
            node = node_rb_right

            while self.get_rb_left(node):
                node = self.get_rb_left(node)
            return node
        parent = self.rb_parent(node)
        while parent and node == self.get_rb_right(parent):
            node = parent
            parent = self.rb_parent(node)
        return parent

    def rb_change_child(self, node, child, parent, root):
        if parent:
            parent_rb_left = self.get_rb_left(parent)
            if parent_rb_left == node:
                self.set_rb_left(parent, child)
            else:
                self.set_rb_right(parent, child)
        else:
            self.ox.ox_write_addr_va(
                root + self.ox.nitro.backend.symbols['offsets']['rb_root']['rb_node'], 0, child)

    def rb_set_parent(self, child, successor):
        child_color = self.rb_color(child)
        self.rb_set_parent_color(child, successor, child_color)

    def rb_erase(self, node, root):
        rebalance = self.rb_erase_augmented(node, root)
        if rebalance:
            self.rb_erase_color(rebalance, root)

    def rb_set_parent_color(self, old, new, color):
        self.ox.ox_write_64_va(
            old + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0, new | color)

    def rb_rotate_set_parents(self, old, new, root, color):
        pc = self.get_rb_pc(old)
        parent = pc & ~3
        self.rb_set_parent_color(new, pc, 0)
        self.rb_set_parent_color(old, new, color)
        self.rb_change_child(old, new, parent, root)

    def rb_color(self, rb):
        pc = self.ox.ox_read_64_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'])
        return pc & 1

    def rb_set_color(self, rb, color):
        pc = self.get_rb_pc(rb)
        self.ox.ox_write_64_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0,
            pc | color)

    def rb_parent(self, node):
        pc = self.ox.ox_read_64_va(
            node + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'])
        return pc & ~3

    def get_rb_right(self, rb):
        return self.ox.ox_read_addr_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0)

    def get_rb_left(self, rb):
        return self.ox.ox_read_addr_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_right'], 0)

    def get_rb_pc(self, rb):
        return self.ox.ox_read_64_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'])

    def set_rb_right(self, rb, value):
        return self.ox.ox_write_addr_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0, value)

    def set_rb_left(self, rb, value):
        return self.ox.ox_write_addr_va(
            rb + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_right'], 0, value)

    def rb_erase_color(self, parent, root):
        node = None
        while True:
            sibling = self.get_rb_right(parent)
            if node != sibling:
                if not self.rb_color(sibling):
                    tmp1 = self.get_rb_left(sibling)
                    self.set_rb_right(sibling, tmp1)
                    self.set_rb_left(sibling, parent)
                    self.rb_set_parent_color(tmp1, parent, 1)
                    self.rb_rotate_set_parents(parent, sibling, root, 0)
                    sibling = tmp1
                tmp1 = self.get_rb_right(sibling)
                if (not tmp1) or self.rb_color(tmp1):
                    tmp2 = self.get_rb_left(sibling)
                    if (not tmp2) or self.rb_color(tmp2):
                        self.rb_set_parent_color(sibling, parent, 0)
                        if not self.rb_color(parent):
                            self.rb_set_color(parent, 1)
                        else:
                            node = parent
                            parent = self.rb_parent(node)
                            if parent:
                                continue
                        break
                    tmp1 = self.get_rb_right(tmp2)
                    self.set_rb_left(sibling, tmp1)
                    self.set_rb_right(tmp2, sibling)
                    self.set_rb_right(parent, tmp2)
                    if tmp1:
                        self.rb_set_parent_color(tmp1, sibling, 1)
                    tmp1 = sibling
                    sibling = tmp2
                tmp2 = self.get_rb_left(sibling)
                self.set_rb_right(parent, tmp2)
                self.set_rb_left(sibling, parent)
                self.rb_set_parent_color(tmp1, sibling, 1)
                if tmp2:
                    self.rb_set_parent(tmp2, parent)
                self.rb_rotate_set_parents(parent, sibling, root, 1)
                break
            else:
                sibling = self.get_rb_left(parent)
                if not self.rb_color(sibling):
                    tmp1 = self.get_rb_right(sibling)
                    self.set_rb_left(parent, tmp1)
                    self.set_rb_right(sibling, parent)
                    self.rb_set_parent_color(tmp1, parent, 1)
                    self.rb_rotate_set_parents(parent, sibling, root, 0)
                    sibling = tmp1
                tmp1 = self.get_rb_left(sibling)
                if (not tmp1) or (self.rb_color(tmp1)):
                    tmp2 = self.get_rb_right(sibling)
                    if (not tmp2) or (self.rb_color(tmp2)):
                        self.rb_set_parent_color(sibling, parent, 0)
                        if not self.rb_color(parent):
                            self.rb_set_color(parent, 1)
                        else:
                            node = parent
                            parent = self.rb_parent(node)
                            if parent:
                                continue
                        break
                    tmp1 = self.get_rb_left(tmp2)
                    self.set_rb_right(sibling, tmp1)
                    self.set_rb_left(tmp2, sibling)
                    self.set_rb_right(parent, tmp2)

                    if tmp2:
                        self.rb_set_parent(tmp2, parent)
                    self.rb_rotate_set_parents(parent, sibling, root, 0)
                    break

    def rb_erase_augmented(self, node, root):
        # struct rb_node * child = node->rb_right;
        child = self.ox.ox_read_addr_va(
            node + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_right'], 0)
        # struct rb_node * tmp = node->rb_left;
        tmp = self.ox.ox_read_addr_va(
            node + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0)
        if not tmp:
            pc = self.ox.ox_read_64_va(
                node + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0)
            parent = pc & ~3

            # __rb_change_child(node, child, parent, root);
            self.rb_change_child(node, child, parent, root)

            if child:
                # child->__rb_parent_color = pc;
                self.ox.ox_write_64_va(
                    child + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0, pc)
                rebalance = None
            else:
                rebalance = parent if pc & 1 else None
            tmp = parent
        elif not child:
            # tmp->__rb_parent_color = pc = node->__rb_parent_color;
            pc = self.ox.ox_read_64_va(
                node + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'])
            self.ox.ox_write_64_va(
                tmp + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0, pc)
            parent = pc & ~3
            self.rb_change_child(node, tmp, parent, root)
            rebalance = None
            tmp = parent
        else:
            successor = child
            tmp = self.ox.ox_read_addr_va(
                child + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0)
            if not tmp:
                parent = successor
                child2 = self.ox.ox_read_addr_va(
                    successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_right'], 0)
            else:
                while True:
                    parent = successor
                    successor = tmp
                    tmp = self.ox.ox_read_addr_va(
                        tmp + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0)
                    if tmp:
                        break
                child2 = self.ox.ox_read_addr_va(
                    successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_right'], 0)
                self.ox.ox_write_addr_va(
                    parent + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0, child2)
                self.ox.ox_write_addr_va(
                    successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_right'], 0, child)
                # rb->__rb_parent_color = rb_color(rb) | (unsigned long)p;
                self.rb_set_parent(child, successor)

            tmp = self.ox.ox_read_addr_va(
                node + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0)
            self.ox.ox_write_addr_va(
                successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['rb_left'], 0, tmp)
            self.rb_set_parent(tmp, successor)
            pc = self.ox.ox_read_64_va(
                node + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'])
            tmp = pc & ~3
            self.rb_change_child(node, successor, tmp, root)

            if child2:
                self.ox.ox_write_64_va(
                    successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0, pc)
                # rb->__rb_parent_color = (unsigned long)p | color;
                self.ox.ox_write_64_va(
                    child2 + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0, successor | 1)
                rebalance = None
            else:
                pc2 = self.ox.ox_read_64_va(
                    successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'])
                self.ox.ox_write_64_va(
                    successor + self.ox.nitro.backend.symbols['offsets']['rb_node']['__rb_parent_color'], 0, pc)
                rebalance = parent if pc2 & 1 else None
            tmp = successor
        return rebalance

    def update_load_sub(self, lw, dec):
        weight = self.ox.ox_read_64_va(lw + self.ox.nitro.backend.symbols['offsets']['load_weight']['weight'], 0)
        self.ox.ox_write_64_va(lw + self.ox.nitro.backend.symbols['offsets']['load_weight']['weight'], 0, weight - dec)
        self.ox.ox_write_32_va(lw + self.ox.nitro.backend.symbols['offsets']['load_weight']['inv_weight'], 0, 0)

    def parent_entity(self, se):
        self.ox.ox_read_addr_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['parent'])

    def account_entity_dequeue(self, cfs_rq, se):
        # self.update_load_sub(
        #     cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['load'],
        #     self.ox.ox_read_64_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['load'] +
        #                           self.ox.nitro.backend.symbols['offsets']['load_weight']['weight'], 0)
        # )
        # if not self.parent_entity(se):
        #     self.update_load_sub(
        #         cfs_rq + cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['rq'] +
        #         self.ox.nitro.backend.symbols['offsets']['rq']['load'],
        #         self.ox.ox_read_64_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['load'] +
        #                               self.ox.nitro.backend.symbols['offsets']['load_weight']['weight'], 0)
        #     )

        nr_running = self.ox.ox_read_32_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['nr_running'], 0)
        self.ox.ox_write_32_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['nr_running'], 0,
                               nr_running - 1)

    def rq_clock_task(self, rq):
        return self.ox.ox_read_64_va(
            rq + self.ox.nitro.backend.symbols['offsets']['rq']['clock_task'], 0)

    def update_curr(self, cfs_rq):
        curr_se = self.ox.ox_read_addr_va(
            cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['curr'], 0)
        rq = self.ox.ox_read_addr_va(
            cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['rq'], 0)
        now = self.rq_clock_task(rq)
        if not curr_se:
            return
        delta_exec = now - self.ox.ox_read_64_va(
            rq + self.ox.nitro.backend.symbols['offsets']['rq']['exec_start'], 0)
        # curr->exec_start = now

    def _dequeue_entity(self, cfs_rq, se):
        # if (cfs_rq->rb_leftmost == &se->run_node)
        cfs_rq_rb_leftmost = self.ox.ox_read_addr_va(
            cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['rb_leftmost'], 0)

        if cfs_rq_rb_leftmost == se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['run_node']:
            # next_node = rb_next(&se->run_node);
            next_node = self.rb_next(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['run_node'])

            # cfs_rq->rb_leftmost = next_node;
            self.ox.ox_write_addr_va(
                cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['rb_leftmost'], 0, next_node)

        self.rb_erase(
            se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['run_node'],
            cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['tasks_timeline']
        )

    def dequeue_entity(self, cfs_rq, se, flags):
        # -update_curr(cfs_rq);
        # -dequeue_entity_load_avg(cfs_rq, se);

        # -update_stats_dequeue(cfs_rq, se, flags);
        # -clear_buddies(cfs_rq, se);

        # --if (cfs_rq->last == se)__clear_buddies_last(se);
        cfs_rq_last = self.ox.ox_read_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['last'],
                                              0)
        if cfs_rq_last == se:
            self.ox.ox_write_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['last'], 0, None)

        # --if (cfs_rq->next == se) __clear_buddies_next(se);
        cfs_rq_next = self.ox.ox_read_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['next'],
                                              0)
        if cfs_rq_next == se:
            self.ox.ox_write_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['next'], 0, None)

        # if (cfs_rq->skip == se) __clear_buddies_skip(se);
        cfs_rq_skip = self.ox.ox_read_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['skip'],
                                              0)
        if cfs_rq_skip == se:
            self.ox.ox_write_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['skip'], 0, None)

        # -if (se != cfs_rq->curr) __dequeue_entity(cfs_rq, se);
        cfs_rq_curr = self.ox.ox_read_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['curr'],
                                              0)
        if se != cfs_rq_curr:
            self._dequeue_entity(cfs_rq, se)

        # -se->on_rq = 0;
        self.ox.ox_write_32_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['on_rq'], 0, 0)
        # -account_entity_dequeue(cfs_rq, se);
        # self.account_entity_dequeue(cfs_rq, se)
        # -if (!(flags & DEQUEUE_SLEEP)) se->vruntime -= cfs_rq->min_vruntime;
        # if not (flags & 0x01):
        #     se_vruntime = self.ox.ox_read_64_va(
        #         se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['vruntime'], 0)
        #     cfs_rq_min_vruntime = self.ox.ox_read_64_va(
        #         cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['min_vruntime'], 0)
        #     self.ox.ox_write_64_va(
        #         se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['vruntime'], 0,
        #         se_vruntime - cfs_rq_min_vruntime)
        # -return_cfs_rq_runtime(cfs_rq);
        # -update_cfs_shares(cfs_rq);
        # -if ((flags & (DEQUEUE_SAVE | DEQUEUE_MOVE)) != DEQUEUE_SAVE) update_min_vruntime(cfs_rq);

    def dequeue_task_fair(self, task, flags):
        se = task + self.ox.nitro.backend.symbols['offsets']['task_struct']['se']
        while se:
            # cfs_rq = cfs_rq_of(se);
            cfs_rq = self.ox.ox_read_addr_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['cfs_rq'], 0)

            # dequeue_entity(cfs_rq, se, flags);
            self.dequeue_entity(cfs_rq, se, flags)

            # if (cfs_rq_throttled(cfs_rq)) break;

            cfs_rq_h_nr_running = self.ox.ox_read_32_va(
                cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['h_nr_running'], 0)
            # cfs_rq->h_nr_running--;
            cfs_rq_h_nr_running = self.ox.ox_read_32_va(
                cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['h_nr_running'], 0)

            # self.ox.ox_write_32_va(
            #     cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['h_nr_running'], 0, cfs_rq_h_nr_running - 1)

            se = self.ox.ox_read_addr_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['parent'], 0)

        se = task + self.ox.nitro.backend.symbols['offsets']['task_struct']['se']
        # while se:
        #     # cfs_rq = cfs_rq_of(se);
        #     cfs_rq = self.ox.ox_read_addr_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['cfs_rq'], 0)
        #
        #     # dequeue_entity(cfs_rq, se, flags);
        #     self.dequeue_entity(cfs_rq, se, flags)
        #
        #     # cfs_rq->h_nr_running--;
        #     cfs_rq_h_nr_running = self.ox.ox_read_32_va(
        #         cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['h_nr_running'], 0)
        #     self.ox.ox_write_32_va(
        #         cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['h_nr_running'], 0, cfs_rq_h_nr_running - 1)
        #
        #     se = self.ox.ox_read_addr_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['parent'], 0)

    def set_flag(self, flags, flag):
        flags |= flag
        return flags

    def list_empty(self, head):
        return self.ox.ox_read_addr_va(head, 0) == head

    def thread_group_empty(self, p):
        return self.list_empty(p + self.ox.nitro.backend.symbols['offsets']['task_struct']['thread_group'])

    def exit_signals(self, tsk, flags):
        if self.thread_group_empty(tsk):
            print("Set flag to PF_EXITING")
            flags = self.set_flag(flags, PF_EXITING)
            return flags
        print("Does not supported yet")

    def get_rq_tsk(self, tsk):
        se = tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['se']
        cfs_rq = self.ox.ox_read_addr_va(se + self.ox.nitro.backend.symbols['offsets']['sched_entity']['cfs_rq'], 0)
        print(hex(cfs_rq))
        rq = self.ox.ox_read_addr_va(cfs_rq + self.ox.nitro.backend.symbols['offsets']['cfs_rq']['rq'], 0)
        return rq

    def do_exit(self, pid):
        print("Killing process with pid {}".format(pid))
        task = self.ox.nitro.backend.get_process(pid)
        if not task:
            print("There aren't any processes with pid: {}".format(pid))
            return
        tsk = task.task_struct
        signal = Signal(self.ox)
        signal.send_signal(tsk, SIGKILL)

        print(tsk, self.ox.nitro.backend.symbols['offsets']['task_struct']['exit_signal'])
        print("Writing sigkill to exit_signal of task")
        self.ox.ox_write_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['exit_signal'], 0, SIGKILL)

        # self.kcov_task_exit(tsk)
        # exit_signals(tsk);
        flags = self.ox.ox_read_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['flags'], 0)
        flags = self.exit_signals(tsk, flags)

        # t->exit_code = 9
        print("Set exit_code ...")
        self.ox.ox_write_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['exit_code'], 0, 9)

        # t->mm = NULL;
        print("Nullify mm ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['mm'], 0, None)

        # tsk->sysvsem.undo_list = NULL;
        print("Nullify sysvsem.undo_list ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['sysvsem'] +
                                 self.ox.nitro.backend.symbols['offsets']['sysv_sem']['undo_list'], 0, None)

        # list_del(&task->sysvshm.shm_clist);

        # tsk->files = NULL;
        print("Nullify files ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['files'], 0, None)

        # tsk->fs = NULL;
        print("Nullify fs ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['fs'], 0, None)

        # p->nsproxy = NULL;
        print("Nullify nsproxy ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['nsproxy'], 0, None)

        # t->io_bitmap_ptr = NULL;
        print("Nullify io_bitmap_ptr ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['thread'] +
                                 self.ox.nitro.backend.symbols['offsets']['thread_struct']['io_bitmap_ptr'], 0, None)

        # t->io_bitmap_max = 0;
        print("Nullify io_bitmap_max ...")
        self.ox.ox_write_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['thread'] +
                               self.ox.nitro.backend.symbols['offsets']['thread_struct']['io_bitmap_max'], 0, 0)
        # sched_move_task
        # self.ox.ox_write_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['exit_signal'], 0, )
        # self.dequeue_task_fair(tsk, 0x02 | 0x04)
        # task->exit_state = EXIT_DEAD
        self.ox.ox_write_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['exit_state'], 0, EXIT_DEAD)

        # task->mempolicy = NULL;
        print("Nullify mempolicy ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['mempolicy'], 0, None)

        # tsk->flags |= PF_EXITPIDONE;
        print("Set flag to PF_EXITPIDONE")
        flags |= PF_EXITPIDONE

        # tsk->io_context = NULL
        print("Nullify io_context ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['io_context'], 0, None)

        # tsk->splice_pipe = NULL
        print("Nullify splice_pipe ...")
        self.ox.ox_write_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['splice_pipe'], 0, None)
        signal.set_tsk_thread_flag(tsk, TIF_NEED_RESCHED)

        # __set_current_state(TASK_DEAD);
        # current->flags |= PF_NOFREEZE;
        print("Set flag to PF_NOFREEZE")
        flags |= PF_NOFREEZE
        self.ox.ox_write_32_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['flags'], 0, flags)

        # __schedule(false);


class Signal:
    def __init__(self, ox):
        self.ox = ox

    def set_bit_32(self, nr, addr):
        bits = self.ox.ox_read_32_va(addr, 0)
        bits |= nr
        self.ox.ox_write_32_va(addr, 0, bits)

    def task_thread_info(self, task):
        return self.ox.ox_read_addr_va(task + self.ox.nitro.backend.symbols['offsets']['task_struct']['stack'], 0)

    def set_ti_thread_flag(self, ti, flag):
        self.set_bit_32(flag, ti + self.ox.nitro.backend.symbols['offsets']['thread_info']['flags'])

    def set_tsk_thread_flag(self, tsk, flag):
        self.set_ti_thread_flag(self.task_thread_info(tsk), flag)

    def wake_up_state(self, p, state):
        print(
            "[warning] Does not implement wake up process yet. If you need to wake up process you must implement it yourself.")
        return False

    def signal_wake_up_state(self, t, state):
        # set_tsk_thread_flag(t, TIF_SIGPENDING);
        self.set_tsk_thread_flag(t, TIF_SIGPENDING)
        # 	/*
        # 	 * TASK_WAKEKILL also means wake it up in the stopped/traced/killable
        # 	 * case. We don't check t->state here because there is a race with it
        # 	 * executing another processor and just now entering stopped state.
        # 	 * By using wake_up_state, we ensure the process will wake up and
        # 	 * handle its death signal.
        # 	 */
        # if (!wake_up_state(t, state | TASK_INTERRUPTIBLE))
        #     kick_process(t);

    def signal_wake_up(self, t, resume):
        self.signal_wake_up_state(t, TASK_WAKEKILL if resume else 0)

    def sigaddset(self, set, _sig):
        sig = _sig - 1
        # set->sig[0] |= 1UL << sig;
        set_sig = self.ox.ox_read_64_va(
            set,
            0
        )
        set_sig |= 1 << sig
        self.ox.ox_write_64_va(
            set,
            0,
            set_sig
        )

    def task_clear_jobctl_pending(self, task, mask):
        if mask & JOBCTL_STOP_PENDING:
            mask |= JOBCTL_STOP_CONSUME | JOBCTL_STOP_DEQUEUED

        task_jobctl = self.ox.ox_read_64_va(
            task + self.ox.nitro.backend.symbols['offsets']['task_struct']['jobctl'],
            0
        )
        task_jobctl &= ~mask
        self.ox.ox_write_64_va(
            task + self.ox.nitro.backend.symbols['offsets']['task_struct']['jobctl'],
            0,
            task_jobctl
        )

        if not (task_jobctl & JOBCTL_PENDING_MASK):
            print("clear jobctl not supported yet")
            # task_clear_jobctl_trapping(task)

    def send_signal(self, tsk, sig=SIGKILL):
        # t = p;
        # do
        # {
        #
        # } while_each_thread(p, t);
        # struct signal_struct *signal = p->signal;
        signal = self.ox.ox_read_addr_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['signal'], 0)

        # signal->flags = SIGNAL_GROUP_EXIT;
        self.ox.ox_write_32_va(
            signal + self.ox.nitro.backend.symbols['offsets']['signal_struct']['flags'],
            0,
            SIGNAL_GROUP_EXIT
        )

        # signal->group_exit_code = sig;
        self.ox.ox_write_32_va(
            signal + self.ox.nitro.backend.symbols['offsets']['signal_struct']['group_exit_code'],
            0,
            SIGKILL
        )

        # signal->group_stop_count = 0;
        self.ox.ox_write_32_va(
            signal + self.ox.nitro.backend.symbols['offsets']['signal_struct']['group_stop_count'],
            0,
            0
        )

        # task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
        self.task_clear_jobctl_pending(task=tsk, mask=JOBCTL_PENDING_MASK)

        # wake task
        self.ox.ox_write_64_va(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['state'], 0, TASK_RUNNING)

        # sigaddset( & t->pending.signal, SIGKILL);
        self.sigaddset(tsk + self.ox.nitro.backend.symbols['offsets']['task_struct']['pending'] +
                       self.ox.nitro.backend.symbols['offsets']['sigpending']['signal'], sig)

        # signal_wake_up(t, 1)
        self.signal_wake_up(tsk, 1)
