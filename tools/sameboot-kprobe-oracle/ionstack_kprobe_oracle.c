// SPDX-License-Identifier: GPL-2.0-only
/*
 * Same-boot, read-only observation oracle for the Violin pselect/PI study.
 *
 * It never modifies the selected task, waiter, fdsets, or scheduler state.
 * It only snapshots values already supplied to do_select() and (when the
 * exact non-inlined symbol exists) rt_mutex_dequeue_pi().
 */
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#define ORACLE_NAME "ionstack_oracle"
#define ORACLE_WORDS 5

/* Mirror fs/select.c's private typedef.  do_select() receives this object
 * only after core_sys_select() completed all three get_fd_set() copies. */
struct ionstack_fd_set_bits {
	unsigned long *in, *out, *ex;
	unsigned long *res_in, *res_out, *res_ex;
};

/* Exact 6.6 GKI layout; keep local to avoid using a non-exported internal
 * locking header when building as an external module. */
struct ionstack_waiter_node {
	struct rb_node entry;
	int prio;
	u64 deadline;
};
struct ionstack_rt_mutex_waiter {
	struct ionstack_waiter_node tree;
	struct ionstack_waiter_node pi_tree;
	struct task_struct *task;
	void *lock;
	unsigned int wake_state;
	void *ww_ctx;
};

struct ionstack_pselect_snapshot {
	pid_t tid, tgid;
	unsigned long stack_base;
	unsigned long in, out, ex;
	unsigned long in_words[ORACLE_WORDS];
	unsigned long out_words[ORACLE_WORDS];
	unsigned long ex_words[ORACLE_WORDS];
	u64 sequence;
	bool valid;
};

struct ionstack_dequeue_snapshot {
	pid_t tid, tgid;
	unsigned long task_arg, waiter;
	unsigned long stack_base;
	unsigned long tree_parent_color, tree_right, tree_left;
	unsigned long pi_parent_color, pi_right, pi_left;
	int pi_prio;
	u64 pi_deadline;
	unsigned long waiter_task, waiter_lock;
	unsigned int wake_state;
	unsigned long ww_ctx;
	s64 delta_from_in, delta_from_out, delta_from_ex;
	s64 expected_waiter_from_in;
	u64 sequence;
	bool valid;
};

static unsigned int target_tgid;
module_param(target_tgid, uint, 0444);
MODULE_PARM_DESC(target_tgid, "Only trace this TGID; 0 traces every process");

static unsigned int pselect_waiter_word_shift;
module_param(pselect_waiter_word_shift, uint, 0444);
MODULE_PARM_DESC(pselect_waiter_word_shift, "Expected PSELECT_WAITER_WORD_SHIFT (normally 0)");

static char *dequeue_symbol = "rt_mutex_dequeue_pi";
module_param(dequeue_symbol, charp, 0444);
MODULE_PARM_DESC(dequeue_symbol, "Exact dequeue symbol; unavailable symbols are reported, never substituted");

static DEFINE_SPINLOCK(snapshot_lock);
static struct ionstack_pselect_snapshot pselect_snapshot;
static struct ionstack_dequeue_snapshot dequeue_snapshot;
static u64 pselect_events;
static u64 dequeue_events;
static bool dequeue_probe_registered;
static int dequeue_probe_error;

static struct kprobe do_select_probe;
static struct kprobe dequeue_probe;

static bool traced_task(const struct task_struct *task)
{
	return !target_tgid || task->tgid == target_tgid;
}

static void copy_words(unsigned long dst[ORACLE_WORDS], const unsigned long *src)
{
	int i;
	for (i = 0; i < ORACLE_WORDS; i++)
		dst[i] = READ_ONCE(src[i]);
}

static int do_select_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct ionstack_fd_set_bits *fds;
	unsigned long flags;
	struct ionstack_pselect_snapshot next = {};

	if (!traced_task(current))
		return 0;
	/* Violin is arm64: x0=n and x1=fds at the do_select() entry. */
	fds = (struct ionstack_fd_set_bits *)regs->regs[1];
	if (!fds || !fds->in || !fds->out || !fds->ex)
		return 0;

	next.tid = current->pid;
	next.tgid = current->tgid;
	next.stack_base = (unsigned long)task_stack_page(current);
	next.in = (unsigned long)fds->in;
	next.out = (unsigned long)fds->out;
	next.ex = (unsigned long)fds->ex;
	copy_words(next.in_words, fds->in);
	copy_words(next.out_words, fds->out);
	copy_words(next.ex_words, fds->ex);
	next.valid = true;

	spin_lock_irqsave(&snapshot_lock, flags);
	next.sequence = ++pselect_events;
	pselect_snapshot = next;
	spin_unlock_irqrestore(&snapshot_lock, flags);
	return 0;
}

static int dequeue_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* Violin is arm64: x0=task and x1=waiter at dequeue entry. */
	struct task_struct *task = (struct task_struct *)regs->regs[0];
	struct ionstack_rt_mutex_waiter *w =
		(struct ionstack_rt_mutex_waiter *)regs->regs[1];
	struct ionstack_dequeue_snapshot next = {};
	unsigned long flags;

	if (!task || !w || !traced_task(task))
		return 0;
	next.tid = current->pid;
	next.tgid = task->tgid;
	next.task_arg = (unsigned long)task;
	next.waiter = (unsigned long)w;
	next.stack_base = (unsigned long)task_stack_page(task);
	next.tree_parent_color = READ_ONCE(w->tree.entry.__rb_parent_color);
	next.tree_right = (unsigned long)READ_ONCE(w->tree.entry.rb_right);
	next.tree_left = (unsigned long)READ_ONCE(w->tree.entry.rb_left);
	next.pi_parent_color = READ_ONCE(w->pi_tree.entry.__rb_parent_color);
	next.pi_right = (unsigned long)READ_ONCE(w->pi_tree.entry.rb_right);
	next.pi_left = (unsigned long)READ_ONCE(w->pi_tree.entry.rb_left);
	next.pi_prio = READ_ONCE(w->pi_tree.prio);
	next.pi_deadline = READ_ONCE(w->pi_tree.deadline);
	next.waiter_task = (unsigned long)READ_ONCE(w->task);
	next.waiter_lock = (unsigned long)READ_ONCE(w->lock);
	next.wake_state = READ_ONCE(w->wake_state);
	next.ww_ctx = (unsigned long)READ_ONCE(w->ww_ctx);
	next.valid = true;

	spin_lock_irqsave(&snapshot_lock, flags);
	if (pselect_snapshot.valid && pselect_snapshot.tgid == task->tgid) {
		next.delta_from_in = (s64)next.waiter - (s64)pselect_snapshot.in;
		next.delta_from_out = (s64)next.waiter - (s64)pselect_snapshot.out;
		next.delta_from_ex = (s64)next.waiter - (s64)pselect_snapshot.ex;
		next.expected_waiter_from_in = (s64)pselect_waiter_word_shift * sizeof(unsigned long);
	}
	next.sequence = ++dequeue_events;
	dequeue_snapshot = next;
	spin_unlock_irqrestore(&snapshot_lock, flags);
	return 0;
}

static void show_words(struct seq_file *m, const char *name, const unsigned long words[ORACLE_WORDS])
{
	seq_printf(m, "%s_w0=%px %s_w1=%px %s_w2=%px %s_w3=%px %s_w4=%px\n",
		name, (void *)words[0], name, (void *)words[1], name, (void *)words[2],
		name, (void *)words[3], name, (void *)words[4]);
}

static int oracle_show(struct seq_file *m, void *v)
{
	struct ionstack_pselect_snapshot ps;
	struct ionstack_dequeue_snapshot dq;
	unsigned long flags;

	spin_lock_irqsave(&snapshot_lock, flags);
	ps = pselect_snapshot;
	dq = dequeue_snapshot;
	spin_unlock_irqrestore(&snapshot_lock, flags);

	seq_printf(m, "oracle=ionstack-kprobe-lkm-readonly\n"
		"target_tgid=%u\nPSELECT_WAITER_WORD_SHIFT=%u\n"
		"do_select_events=%llu\nrt_mutex_dequeue_pi_events=%llu\n"
		"rt_mutex_dequeue_pi_probe=%s\nrt_mutex_dequeue_pi_probe_error=%d\n",
		target_tgid, pselect_waiter_word_shift,
		(unsigned long long)pselect_events, (unsigned long long)dequeue_events,
		dequeue_probe_registered ? "registered" : "unavailable", dequeue_probe_error);
	if (ps.valid) {
		seq_printf(m, "pselect_tid=%d\npselect_tgid=%d\npselect_stack_base=%px\n"
			"pselect_fdset_in=%px\npselect_fdset_out=%px\npselect_fdset_ex=%px\n"
			"pselect_sequence=%llu\n",
			ps.tid, ps.tgid, (void *)ps.stack_base, (void *)ps.in,
			(void *)ps.out, (void *)ps.ex, (unsigned long long)ps.sequence);
		show_words(m, "pselect_in", ps.in_words);
		show_words(m, "pselect_out", ps.out_words);
		show_words(m, "pselect_ex", ps.ex_words);
	}
	if (dq.valid) {
		seq_printf(m, "dequeue_tid=%d\ndequeue_tgid=%d\ndequeue_task_arg=%px\n"
			"waiter_kernel_stack_address=%px\nwaiter_task_stack_base=%px\n"
			"waiter_tree_parent_color=%px\nwaiter_tree_right=%px\nwaiter_tree_left=%px\n"
			"waiter_pi_parent_color=%px\nwaiter_pi_right=%px\nwaiter_pi_left=%px\n"
			"waiter_pi_prio=%d\nwaiter_pi_deadline=%llu\nwaiter_task=%px\n"
			"waiter_lock=%px\nwaiter_wake_state=%u\nwaiter_ww_ctx=%px\n"
			"waiter_minus_pselect_in=%lld\nwaiter_minus_pselect_out=%lld\n"
			"waiter_minus_pselect_ex=%lld\n"
			"expected_waiter_minus_pselect_in_for_shift=%lld\n"
			"dequeue_sequence=%llu\n",
			dq.tid, dq.tgid, (void *)dq.task_arg, (void *)dq.waiter,
			(void *)dq.stack_base, (void *)dq.tree_parent_color,
			(void *)dq.tree_right, (void *)dq.tree_left,
			(void *)dq.pi_parent_color, (void *)dq.pi_right, (void *)dq.pi_left,
			dq.pi_prio, (unsigned long long)dq.pi_deadline, (void *)dq.waiter_task,
			(void *)dq.waiter_lock, dq.wake_state, (void *)dq.ww_ctx,
			(long long)dq.delta_from_in, (long long)dq.delta_from_out,
			(long long)dq.delta_from_ex, (long long)dq.expected_waiter_from_in,
			(unsigned long long)dq.sequence);
	}
	return 0;
}

static int oracle_open(struct inode *inode, struct file *file)
{
	return single_open(file, oracle_show, NULL);
}

static const struct proc_ops oracle_ops = {
	.proc_open = oracle_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init oracle_init(void)
{
	int ret;
	do_select_probe.symbol_name = "do_select";
	do_select_probe.pre_handler = do_select_pre;
	ret = register_kprobe(&do_select_probe);
	if (ret)
		return ret;

	dequeue_probe.symbol_name = dequeue_symbol;
	dequeue_probe.pre_handler = dequeue_pre;
	dequeue_probe_error = register_kprobe(&dequeue_probe);
	if (!dequeue_probe_error)
		dequeue_probe_registered = true;
	if (!proc_create(ORACLE_NAME, 0444, NULL, &oracle_ops)) {
		if (dequeue_probe_registered)
			unregister_kprobe(&dequeue_probe);
		unregister_kprobe(&do_select_probe);
		return -ENOMEM;
	}
	pr_info("ionstack oracle: do_select probe active; dequeue probe=%s err=%d\n",
		dequeue_probe_registered ? "active" : "unavailable", dequeue_probe_error);
	return 0;
}

static void __exit oracle_exit(void)
{
	remove_proc_entry(ORACLE_NAME, NULL);
	if (dequeue_probe_registered)
		unregister_kprobe(&dequeue_probe);
	unregister_kprobe(&do_select_probe);
}

module_init(oracle_init);
module_exit(oracle_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only same-boot pselect/rt-mutex kprobe oracle");
