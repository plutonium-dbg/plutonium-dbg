#ifndef CONFIG_KALLSYMS
#error plutonium-dbg requires kallsyms support (use a kernel with CONFIG_KALLSYMS=y, this should be enabled by default)
#endif
#ifndef CONFIG_KPROBES
#error plutonium-dbg requires Kprobes support (use a kernel with CONFIG_KPROBES=y, this should be enabled by default)
#endif
#ifndef CONFIG_UPROBES
#error plutonium-dbg requires Uprobes support (use a kernel with CONFIG_UPROBES=y, this should be enabled by default)
#endif

#include <linux/binfmts.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/regset.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>

#include <trace/events/signal.h>

#include "types.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tobias Holl <tobias.holl@tum.de>, Philipp Klocke <philipp.klocke@tum.de>");
MODULE_DESCRIPTION("Kernel-assisted debugger for userspace applications");



/* Global data and forward declarations */

static int handle_breakpoint(struct uprobe_consumer *self, struct pt_regs *regs);
static int handle_suspension_breakpoint(struct uprobe_consumer *self, struct pt_regs *regs);
static void __push_event(struct debugger *dbg, pid_t victim_tid, int event_id, union event_data data);

static DEFINE_MUTEX(data_mutex);
static DEFINE_MUTEX(suspension_mutex);
static DEFINE_HASHTABLE(victims, 4);
static DEFINE_HASHTABLE(debuggers, 4);
static DEFINE_HASHTABLE(exiting, 4);
static DEFINE_HASHTABLE(signal_canceled, 4);
static LIST_HEAD(pending_suspensions);
static struct workqueue_struct *deferred_queue;

static unsigned long (*ks_wait_task_inactive)(struct task_struct *, long);
static void (*ks_user_enable_single_step)(struct task_struct *);
static void (*ks_user_disable_single_step)(struct task_struct *);
static int (*ks_get_signal)(struct ksignal *);
static int (*ks_dequeue_signal)(struct task_struct *, sigset_t *, siginfo_t *);
static int (*ks_security_ptrace_access_check)(struct task_struct *, unsigned int);

static struct kretprobe signal_probe;
static bool module_unloading = false;



/* Helper macros */

#ifdef MOD_DEBUG_ENABLE_TRACE
#pragma message "Tracing is enabled. Undefine MOD_DEBUG_ENABLE_TRACE for production."
#define TRACE(...) printk(KERN_INFO "[TRACE]: " __VA_ARGS__)
#else
#define TRACE(...)
#endif

#ifdef MOD_DEBUG_ENABLE_MUTEX_TRACE
#pragma message "Mutex tracing is enabled. Undefine MOD_DEBUG_ENABLE_MUTEX_TRACE for production."
#define MUTEX_TRACE(message, name) printk(KERN_INFO "[MUTEX]: %s %s (TID %d on line %d in %s)\n", message, name, current->pid, __LINE__, __FUNCTION__)
#undef mutex_lock
#define mutex_lock(lock)           (void) (MUTEX_TRACE("Locking", #lock), mutex_lock_nested(lock, 0) /* Need to use this because mutex_lock is a macro */, MUTEX_TRACE("Locked", #lock), 0)
#define mutex_unlock(lock)         (void) (MUTEX_TRACE("Unlocking", #lock), mutex_unlock(lock), MUTEX_TRACE("Unlocked", #lock), 0)
#endif

/** Hashes a pid_t to four bits */
#define HASH_ID(id) ((id) & 0xF)

/** Allocates memory using kmalloc **/
#define ALLOC_PTR(var) likely((var = kmalloc(sizeof(*var), GFP_KERNEL)) != NULL)

/** Cleanup actions with value-return **/
#define cleanup_and_return(value, ...) do { (void) (__VA_ARGS__, 0); return value; } while (0)
#define cleanup_and_return_void(...) do { (void) (__VA_ARGS__, 0); return; } while (0)

/** Finds an entry in a list */
#define FIND_LIST_ENTRY(ptr, head, member, condition) \
	do { \
		list_for_each_entry(ptr, (head), member) \
			if (condition) \
				break; \
		/* Check if we looped all the way */ \
		if (&ptr->member == (head)) \
			ptr = NULL; \
	} while (0)

/** Counterpart to containerof **/
#define PTR_AT(base_addr, type, member) (((char *) base_addr) + offsetof(type, member))



/* Access control */

/**
 * check_access - Checks whether the current process is allowed to debug the target
 * @target: The target thread or process
 *
 * Returns -ESRCH if the task does not exist.
 * Returns -EPERM if access is denied.
 * Returns 0 if access is granted.
 *
 * Access is granted if (a) the requesting thread is in the same thread group as
 * the target, (b) the requesting process already has the permission to ptrace
 * arbitrary processes (CAP_SYS_PTRACE), or (c)
 *  - the requesting process' EUID equals the target's EUID, RUID, and SUID, and
 *  - the requesting process' EGID equals the target's EGID, RGID, and SGID.
 * For (c), we check the target's RUID (to ensure that processes which drop
 * privileges can only be debugged by their owner or someone allowed to
 * impersonate that owner), EUID (to ensure that processes with elevated
 * privileges can only be debugged by someone with at least equivalent
 * privileges), and SUID (to avoid any nasty surprises). This means that the
 * "user history" (which user started the process, and what user it switched to)
 * needs to be replicated exactly by the requesting process. On multi-user
 * systems, this ensures that a privilege-dropping process owned by A cannot
 * simply be debugged by a privilege-dropping process owned by B.
 *
 * For (c), we could additionally check whether ptrace access was limited by a
 * kernel security module such as Yama (via yama.ptrace_scope) via
 * security_ptrace_access_check, but the relevant functions are not exported by
 * the kernel. We may revisit enabling this option to enhance security.
 */
static int check_access(pid_t target)
{
	int                 uid_check;
	int                 gid_check;
	int                 flags;
	int                 lsm_result;
	bool                capable;
	struct task_struct *task;
	const struct cred  *t_cred;
	kuid_t              r_euid;
	kgid_t              r_egid;

	/* Get the task */
	rcu_read_lock();
	task = pid_task(find_vpid(target), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return(-ESRCH, rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	t_cred = __task_cred(task);

	/* Check thread groups */
	if (same_thread_group(current, task))
		cleanup_and_return(0, put_task_struct(task)); /* No delegation to LSM here */

	/* Check global ptrace capability */
	flags = current->flags;
	capable = ns_capable(t_cred->user_ns, CAP_SYS_PTRACE);
	if (!(flags & PF_SUPERPRIV))
		current->flags &= ~PF_SUPERPRIV; /* ns_capable sets PF_SUPERPRIV, reset the state of that flag */

	if (capable)
		goto lsm;

	/* Manually check IDs */
	r_euid = current_euid();
	r_egid = current_egid();

	uid_check = uid_eq(r_euid, t_cred->euid) && uid_eq(r_euid, t_cred->uid) && uid_eq(r_euid, t_cred->suid);
	gid_check = gid_eq(r_egid, t_cred->egid) && gid_eq(r_egid, t_cred->gid) && gid_eq(r_egid, t_cred->sgid);
	if (uid_check && gid_check)
		goto lsm;

	/* By default, deny access */
	put_task_struct(task);
	return -EPERM;

lsm:
	/* Delegate to LSM */
	if (ks_security_ptrace_access_check != NULL) {
		/* Check with the installed LSMs */
		lsm_result = ks_security_ptrace_access_check(task, PTRACE_MODE_REALCREDS);
	} else {
		/* We passed all checks so far, and no LSM restricts access */
		lsm_result = 0;
	}
	put_task_struct(task);
	return (lsm_result == 0) ? 0 : -EPERM;
}



/* Utility functions */

/**
 * tgid_from_tid - Gets the (process-wide) TGID for a thread's TID
 * @tid: The TID whose TGID is requested
 *
 * Returns the TGID, or -ESRCH on failure.
 */
static pid_t tgid_from_tid(pid_t tid)
{
	struct task_struct *task;
	pid_t               tgid;
	TRACE("tgid_from_tid(%d)\n", tid);

	rcu_read_lock();
	task = pid_task(find_vpid(tid), PIDTYPE_PID);
	tgid = (task == NULL) ? -ESRCH : task->tgid;
	rcu_read_unlock();

	return tgid;
}

/**
 * compute_location - computes the location of the breakpoint as an inode/offset pair
 * @location: The location to write to
 * @target:   The target TGID or TID
 * @address:  The address of the breakpoint
 *
 * Returns -ESRCH  if the target task does not exist.
 * Returns -EACCES if the target has no memory map (likely a kernel task)
 * Returns -EFAULT if the target address is not mapped
 * Returns -EBADF  if the target address has no inode
 */
static int compute_location(struct probe_location *location, pid_t target, addr_t address)
{
	struct task_struct    *task;
	struct mm_struct      *mm;
	struct vm_area_struct *vma;
	TRACE("compute_location(%p, %d, %lx)\n", location, target, address);

	/* Get the memory mapping for this process */
	rcu_read_lock();
	task = pid_task(find_vpid(target), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return(-ESRCH, rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	mm = get_task_mm(task);
	if (mm == NULL)
		cleanup_and_return(-EACCES, put_task_struct(task));

	vma = find_vma(mm, address);
	if (vma == NULL)
		cleanup_and_return(-EFAULT, mmput(mm), put_task_struct(task));

	/* Get the inode and offset */
	if (vma->vm_file == NULL || vma->vm_file->f_inode == NULL)
		cleanup_and_return(-EBADF, mmput(mm), put_task_struct(task));

	location->inode  = vma->vm_file->f_inode;
	location->offset = (loff_t) (address - vma->vm_start + vma->vm_pgoff * PAGE_SIZE);

	mmput(mm);
	put_task_struct(task);
	return 0;
}

/**
 * delete_dead_breakpoint - Cleans up a dead breakpoint.
 * @work: The work_struct for the deferred task.
 */
static void delete_dead_breakpoint(struct work_struct *work)
{
	struct dead_breakpoint *dead = container_of(work, struct dead_breakpoint, work);

	TRACE("Deleting dead breakpoint probe <%d:%lx> := <%lu:%lld>\n", dead->bp->target, dead->bp->address, dead->bp->probe.inode->i_ino, dead->bp->probe.offset);
	uprobe_unregister(dead->bp->probe.inode, dead->bp->probe.offset, &dead->bp->handler);
	kfree(dead->bp);
	kfree(dead);
}

/**
 * __mark_exiting - Adds or removes a thread from the list of currently exiting tasks
 * @tid:   TID of the thread in question
 * @state: Whether the thread is exiting
 */
static void __mark_exiting(pid_t tid, bool state)
{
	struct thread_marker *marker;
	TRACE("__mark_exiting(%d, %d)\n", tid, state);
	if (state) {
		hash_for_each_possible(exiting, marker, node, HASH_ID(tid))
			if (marker->tid == tid)
				return;
		if (!ALLOC_PTR(marker))
			cleanup_and_return_void(printk(KERN_ERR "Could not allocate space for exit marker\n"));
		marker->tid = tid;
		hash_add(exiting, &marker->node, HASH_ID(tid));
	} else {
		hash_for_each_possible(exiting, marker, node, HASH_ID(tid)) {
			if (marker->tid == tid) {
				hash_del(&marker->node);
				kfree(marker);
				return;
			}
		}
	}
}

/**
 * __is_exiting - Checks whether a thread is exiting
 * @tid: TID of the thread
 */
static bool __is_exiting(pid_t tid)
{
	struct thread_marker *marker;
	hash_for_each_possible(exiting, marker, node, HASH_ID(tid))
		if (marker->tid == tid)
			return true;
	return false;
}

/**
 * __restore_sigactions - Restores the damaged sigactions from signal_canceled
 */
static void __restore_sigactions(void)
{
	struct cancellation *cancel;
	struct hlist_node   *tmp;
	hash_for_each_possible_safe(signal_canceled, cancel, tmp, node, HASH_ID(current->pid)) {
		if (cancel->tid == current->pid && cancel->state != CANCELLATION_PENDING) {
			if (cancel->state == CANCELLATION_MUST_RESTORE)
				cancel->action->sa.sa_handler = cancel->handler;
			hash_del(&cancel->node);
			kfree(cancel);
		}
	}
}



/* Thread suspension */

/**
 * suspend_thread - Places the target thread in a suspended (but killable) state
 * @tid: TID of the target thread
 */
static void suspend_thread(pid_t tid)
{
	struct task_struct *task;
	struct breakpoint  *bp;
	struct pt_regs      reg_copy;
	int                 result;
	TRACE("suspend_thread(%d)\n", tid);

	rcu_read_lock();
	task = pid_task(find_vpid(tid), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return_void(rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	if (current->pid != tid) {
		TRACE("suspending foreign thread (%d => %d)\n", current->pid, task->pid);
		mutex_lock(&suspension_mutex);

		/* If the target thread has a pending suspension, do nothing */
		FIND_LIST_ENTRY(bp, &pending_suspensions, node, bp->target == tid);
		if (bp != NULL)
			cleanup_and_return_void(mutex_unlock(&suspension_mutex), put_task_struct(task));

		/* Allocate a temporary breakpoint */
		if (!ALLOC_PTR(bp)) {
			printk(KERN_ERR "Out of memory: cannot suspend foreign thread %d", tid);
			cleanup_and_return_void(mutex_unlock(&suspension_mutex), put_task_struct(task));
		}

		/* NB: If the process is already in kernel space, we are in trouble.
		 * Imagine that the process is currently in sleep(...). Then, it is
		 * TASK_INTERRUPTIBLE in kernel space, and upon wakeup will automatically
		 * be set to TASK_RUNNING.
		 * Instead, we set the task to __TASK_TRACED (which is what ptrace uses internally).
		 * This will forcibly suspend the thread.
		 * We do not want to maintain that state because it is easily detectable from
		 * userspace, so we set a breakpoint at the current instruction.
		 */
		smp_store_mb(task->state, __TASK_TRACED);
		set_tsk_thread_flag(task, TIF_NEED_RESCHED);
		kick_process(task); /* This forces a scheduler interrupt (see scheduler_ipi()) */
		ks_wait_task_inactive(task, __TASK_TRACED);

		/* Copy the task's registers */
		if (copy_from_user(&reg_copy, task_pt_regs(task), sizeof(reg_copy)) != sizeof(reg_copy))
			printk(KERN_ERR "Could not read registers for TID %d.\n", tid);

		/* Set a temporary breakpoint at the instruction pointer to hand control to plutonium-dbg */
		bp->target              = tid;
		bp->address             = instruction_pointer(&reg_copy);
		bp->probe.inode         = NULL;
		bp->probe.offset        = 0;
		bp->handler.handler     = &handle_suspension_breakpoint;
		bp->handler.ret_handler = NULL;
		bp->handler.filter      = NULL;
		bp->handler.next        = NULL;

		TRACE("submitting tbp at %p\n", bp);
		list_add_tail(&bp->node, &pending_suspensions);
		mutex_unlock(&suspension_mutex);

		result = compute_location(&bp->probe, bp->target, bp->address);
		if (result != 0)
			printk(KERN_ERR "Could not compute location of suspension probe for TID %d at address %lx: Error %d.\n", tid, bp->address, result);
		TRACE("suspension for TID %d, IP %lx as %lu:%lld\n", tid, bp->address, bp->probe.inode->i_ino, bp->probe.offset);
		if (uprobe_register(bp->probe.inode, bp->probe.offset, &bp->handler) != 0)
			printk(KERN_ERR "Could not register suspension probe for TID %d at address %lx.\n", tid, bp->address);

		/* Wake up the process so we hit the breakpoint */
		smp_store_mb(task->state, TASK_KILLABLE);
		wake_up_process(task);
	} else {
		smp_store_mb(task->state, TASK_KILLABLE);
	}
	put_task_struct(task);
}

/**
 * wake_up_thread - Wakes up a thread previously suspended by suspend_thread
 * @tid: TID of the target thread
 */
static void wake_up_thread(pid_t tid)
{
	struct breakpoint  *bp;
	struct task_struct *task;
	TRACE("wake_up_thread(%d)\n", tid);

	rcu_read_lock();
	task = pid_task(find_vpid(tid), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return_void(rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	if (task == NULL)
		return;

	/* If the target thread has a pending suspension, do nothing */
	mutex_lock(&suspension_mutex);
	FIND_LIST_ENTRY(bp, &pending_suspensions, node, bp->target == tid);
	if (bp != NULL)
		cleanup_and_return_void(mutex_unlock(&suspension_mutex), put_task_struct(task));
	mutex_unlock(&suspension_mutex);

	TRACE("waking thread %d\n", task->pid);
	wake_up_process(task);
	put_task_struct(task);
}



/* Basic data structure creation and destruction */

/**
 * __get_debugger - Returns the debugger entry for the given TGID, or NULL
 * @debugger_tgid: TGID of the debugger
 *
 * Returns a pointer to the debugger entry.
 */
static struct debugger *__get_debugger(pid_t debugger_tgid)
{
	struct debugger *dbg;
	TRACE("__get_debugger(%d)\n", debugger_tgid);

	/* Return an existing entry if it exists */
	hash_for_each_possible(debuggers, dbg, node, HASH_ID(debugger_tgid))
		if (dbg->tgid == debugger_tgid)
			return dbg;

	/* No entry */
	return NULL;
}

/**
 * __debugger - Returns the debugger entry for the given TGID, creating a new entry if needed
 * @debugger_tgid: TGID of the debugger
 *
 * Returns a pointer to the debugger entry.
 * Returns -ENOMEM if allocation fails.
 */
static struct debugger *__debugger(pid_t debugger_tgid)
{
	struct debugger *dbg;
	TRACE("__debugger(%d)\n", debugger_tgid);

	/* Return an existing entry if it exists */
	dbg = __get_debugger(debugger_tgid);
	if (dbg != NULL)
		return dbg;

	/* Allocate space for the new entry */
	if (!ALLOC_PTR(dbg))
		return ERR_PTR(-ENOMEM);

	/* Set up values */
	dbg->tgid = debugger_tgid;
	INIT_LIST_HEAD(&dbg->breakpoints);
	INIT_LIST_HEAD(&dbg->locks);
	INIT_LIST_HEAD(&dbg->event_queue);

	/* Add to the hash table */
	hash_add(debuggers, &dbg->node, HASH_ID(debugger_tgid));

	return dbg;
}

/**
 * __get_victim - Returns the victim entry for the given TID, or NULL
 * @victim_tid: TID of the victim thread (can also be a TGID)
 *
 * Returns a pointer to the victim entry.
 * Returns -ESRCH if the process does not exist
 */
static struct victim *__get_victim(pid_t victim_tid)
{
	pid_t          tgid;
	struct victim *vct;
	TRACE("__get_victim(%d)\n", victim_tid);

	/* Get the TGID */
	tgid = tgid_from_tid(victim_tid);
	if (tgid == -ESRCH)
		return ERR_PTR(-ESRCH);

	/* Return an existing entry if it exists */
	hash_for_each_possible(victims, vct, node, HASH_ID(tgid))
		if (vct->tgid == tgid)
			return vct;

	/* No entry */
	return NULL;
}

/**
 * __victim - Returns the victim entry for the given TID, creating a new entry if needed
 * @victim_tid: TID of the victim thread (can also be a TGID, because TGID == TID for the lead thread)
 *
 * Returns a pointer to the victim entry.
 * Returns -ENOMEM if allocation fails
 * Returns -ESRCH  if the process does not exist
 */
static struct victim *__victim(pid_t victim_tid)
{
	pid_t          tgid;
	struct victim *vct;
	TRACE("__victim(%d)\n", victim_tid);

	/* Try to get an existing victim entry */
	vct = __get_victim(victim_tid);
	if (vct != NULL)
		return vct; /* Error or existing entry */

	/* Get the TGID */
	tgid = tgid_from_tid(victim_tid);
	if (tgid == -ESRCH)
		return ERR_PTR(-ESRCH);

	/* Allocate space for the new entry */
	if (!ALLOC_PTR(vct))
		return ERR_PTR(-ENOMEM);

	/* Set up values */
	vct->tgid = tgid;
	INIT_LIST_HEAD(&vct->breakpoints);
	INIT_LIST_HEAD(&vct->locks);
	INIT_LIST_HEAD(&vct->step_listeners);
	INIT_LIST_HEAD(&vct->event_listeners);

	/* Add to the hash table */
	hash_add(victims, &vct->node, HASH_ID(tgid));

	return vct;
}

/**
 * __breakpoint - Returns the breakpoint entry for the given victim and address, creating a new entry (with probe) if needed
 * @victim_tid: TID or TGID of the victim (remember that breakpoints are process-wide, and that TID filtering should happen on the user side)
 * @addr:       Address in the victim's address space
 *
 * Returns a pointer to the breakpoint entry.
 * Returns -ENOMEM if allocation fails.
 * Returns any error produced by __victim, compute_location or uprobe_register.
 */
static struct breakpoint *__breakpoint(pid_t victim_tid, addr_t addr)
{
	struct victim     *vct;
	struct breakpoint *bp;
	int                result;
	TRACE("__breakpoint(%d, %lx)\n", victim_tid, addr);

	/* Get the victim */
	vct = __victim(victim_tid);
	if (IS_ERR(vct))
		return ERR_CAST(vct);

	/* Check if the breakpoint already exists */
	list_for_each_entry(bp, &vct->breakpoints, node)
		if (bp->address == addr)
			return bp;

	/* Create a new breakpoint */
	if (!ALLOC_PTR(bp))
		return ERR_PTR(-ENOMEM);

	bp->target  = vct->tgid;
	bp->address = addr;
	INIT_LIST_HEAD(&bp->attached);

	bp->probe.inode  = NULL;
	bp->probe.offset = 0;

	bp->handler.handler     = &handle_breakpoint;
	bp->handler.ret_handler = NULL;
	bp->handler.filter      = NULL;
	bp->handler.next        = NULL;

	atomic_set(&bp->counter, 0);
	bp->state = BP_STATE_ACTIVE;

	/* Install the probe */
	result = compute_location(&bp->probe, bp->target, bp->address);
	if (result != 0) {
		printk(KERN_ERR "Could not find probe location for TGID %d, address %lx: Error %d.\n", victim_tid, addr, result);
		kfree(bp);
		return ERR_PTR(result);
	}
	result = uprobe_register(bp->probe.inode, bp->probe.offset, &bp->handler);
	if (result != 0) {
		printk(KERN_ERR "Could not register probe for TGID %d, address %lx: Error %d.\n", victim_tid, addr, result);
		kfree(bp);
		return ERR_PTR(result);
	}

	list_add_tail(&bp->node, &vct->breakpoints);

	return bp;
}

/**
 * __delete_victim - Removes the given victim entry.
 * @vct: The victim to remove
 */
static void __delete_victim(struct victim *vct)
{
	struct event_listener *lst;
	struct event_listener *it;

	TRACE("__delete_victim(%p <%d>)\n", vct, vct->tgid);
	if (unlikely(!list_empty(&vct->breakpoints))) {
		printk(KERN_ERR "Trying to remove victim %d while it still has active breakpoints\n", vct->tgid);
		return;
	}
	if (unlikely(!list_empty(&vct->locks))) {
		printk(KERN_ERR "Trying to remove victim %d while it still has locked threads\n", vct->tgid);
		return;
	}
	if (unlikely(!list_empty(&vct->step_listeners))) {
		printk(KERN_ERR "Trying to remove victim %d while it still has attached single-step listeners\n", vct->tgid);
		return;
	}

	hash_del(&vct->node);

	list_for_each_entry_safe(lst, it, &vct->event_listeners, node) {
		list_del(&lst->node);
		kfree(lst);
	}

	kfree(vct);
}

/**
 * __delete_breakpoint - Removes the given breakpoint.
 * @bp: The breakpoint to remove
 */
static void __delete_breakpoint(struct breakpoint *bp)
{
	struct dead_breakpoint *deferred;
	TRACE("__delete_breakpoint(%p <%d,%lx>)\n", bp, bp->target, bp->address);

	if (unlikely(!list_empty(&bp->attached))) {
		printk(KERN_ERR "Trying to remove breakpoint at TGID %d, address %lx while still in use\n", bp->target, bp->address);
		return;
	}

	/* Set to dead state so we do not deadlock if the probe is hit afterwards */
	smp_store_mb(bp->state, BP_STATE_DEAD);

	smp_mb__before_atomic();
	if (atomic_read(&bp->counter) > 0)
		return;

	list_del(&bp->node);

	if (bp->probe.inode != NULL || compute_location(&bp->probe, bp->target, bp->address) == 0) {
		/* Unregister this breakpoint from another task that can block if necessary */
		if (!ALLOC_PTR(deferred)) {
			printk(KERN_ERR "Could not defer cleanup for breakpoint at TGID %d, address %lx\n", bp->target, bp->address);
			return;
		}
		INIT_WORK(&deferred->work, delete_dead_breakpoint);
		deferred->bp = bp;
		queue_work(deferred_queue, &deferred->work);
	} else {
		/* Free the breakpoint immediately if there is no attached probe */
		kfree(bp);
	}
}

/**
 * __delete_debugger - Destroys the given debugger. Continues all stopped tasks.
 * @dbg: The debugger to destroy
 */
static void __delete_debugger(struct debugger *dbg)
{
	struct thread_lock     *lck;
	struct thread_lock     *lck_it;
	struct thread_lock     *duplicate;
	struct attached_config *cfg;
	struct attached_config *cfg_it;
	struct victim          *vct;
	struct event           *evt;
	struct event           *evt_it;

	struct list_head removed;
	INIT_LIST_HEAD(&removed);

	TRACE("__delete_debugger(%p <%d>)\n", dbg, dbg->tgid);


	if (unlikely(!list_empty(&dbg->breakpoints))) {
		printk(KERN_ERR "Trying to remove debugger %d with active breakpoints\n", dbg->tgid);
		return;
	}

	/* Release all thread locks */
	list_for_each_entry_safe(lck, lck_it, &dbg->locks, debugger_node) {
		list_del(&lck->victim_node);
		list_del(&lck->debugger_node);

		vct = __get_victim(lck->victim_tid);
		if (vct != NULL) {
			FIND_LIST_ENTRY(duplicate, &vct->locks, victim_node, duplicate->victim_tid == lck->victim_tid);
			if (duplicate == NULL)
				wake_up_thread(lck->victim_tid);
		}

		kfree(lck);
	}

	/* Detach from all the breakpoints */
	list_for_each_entry_safe(cfg, cfg_it, &dbg->breakpoints, debugger_node) {
		list_del(&cfg->breakpoint_node);
		list_del(&cfg->debugger_node);

		if (cfg->breakpoint_ref != NULL && list_empty(&cfg->breakpoint_ref->attached)) {
			__delete_breakpoint(cfg->breakpoint_ref);

			vct = __get_victim(cfg->breakpoint_ref->target);
			if (IS_ERR(vct) || vct == NULL)
				continue;
			if (list_empty(&vct->breakpoints) && list_empty(&vct->locks) && list_empty(&vct->step_listeners))
				__delete_victim(vct);
		}

		kfree(cfg);
	}

	/* Clean up all events */
	list_for_each_entry_safe(evt, evt_it, &dbg->event_queue, node) {
		list_del(&evt->node);
		kfree(evt);
	}

	hash_del(&dbg->node);
	kfree(dbg);
}



/* Thread locks */

/**
 * __suspend_loop - Keeps the current thread in a suspend loop until no more locks are held
 */
static void __suspend_loop(void)
{
	struct victim      *vct;
	struct thread_lock *lck;

	TRACE("TID %d in __suspend_loop()\n", current->pid);

	mutex_unlock(&data_mutex);

	/* While we are locked, keep suspending the current thread explicitly, then reschedule. */
	for (;;) {
		mutex_lock(&data_mutex);

		/* Check for locks */
		vct = __get_victim(current->tgid);
		if (IS_ERR(vct) || vct == NULL || list_empty(&vct->locks))
			return;
		FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->victim_tid == current->pid);
		if (lck == NULL)
			return;

		mutex_unlock(&data_mutex);

		/* Suspend and reschedule */
		suspend_thread(current->pid);
		schedule();
	}
}

/**
 * lock_thread - Locks a thread for a debugger
 * @debugger_tgid: TGID of the debugger holding the lock
 * @victim_tid:    TID of the victim thread
 * @reason:        Lock reason
 *
 * Returns 0 on success.
 * Returns -EOWNERDEAD when trying to suspend a foreign thread that is currently exiting
 * Returns -EEXIST if the lock is already held.
 * Returns -ENOMEM if allocation fails.
 * Returns any error from __debugger and __victim.
 */
static int __lock_thread(pid_t debugger_tgid, pid_t victim_tid, int reason)
{
	struct debugger    *dbg;
	struct thread_lock *lck;
	struct victim      *vct;
	union event_data    evt_data;
	bool                suspend;
	bool                submit;
	TRACE("lock_thread(%d, %d)\n", debugger_tgid, victim_tid);

	/* Get the debugger entry corresponding to the given TGID */
	dbg = __debugger(debugger_tgid);
	if (IS_ERR(dbg))
		return PTR_ERR(dbg);

	/* Get the victim entry from the given TID */
	vct = __victim(victim_tid);
	if (IS_ERR(vct))
		return PTR_ERR(vct);
	if (__is_exiting(victim_tid))
		return -EOWNERDEAD;

	/* Check that the lock does not already exist and allocate a new one */
	FIND_LIST_ENTRY(lck, &dbg->locks, debugger_node, lck->victim_tid == victim_tid);
	if (lck != NULL)
		return -EEXIST;
	FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->victim_tid == victim_tid);
	suspend = (lck == NULL); /* Only suspend threads the first time */
	FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->victim_tid == victim_tid && lck->event_submitted);
	submit = (reason != SUSPEND_EXPLICIT) || (!suspend && (lck == NULL)); /* We submit events unless this is an explicit suspend with no already-submitted events */
	if (!ALLOC_PTR(lck))
		return -ENOMEM;

	TRACE("__lock_thread <debugger %d> <victim %d>: suspend = %s, submit = %s\n", debugger_tgid, victim_tid, suspend ? "true" : "false", submit ? "true" : "false");

	/* Add the lock to both lists and set its members. */
	list_add_tail(&lck->victim_node, &vct->locks);
	list_add_tail(&lck->debugger_node, &dbg->locks);
	lck->victim_tid = victim_tid;
	lck->debugger_tgid = debugger_tgid;
	lck->reason = reason;
	lck->event_submitted = submit;

	/* Suspend the victim task */
	evt_data.suspension_reason = reason;
	if (suspend)
		suspend_thread(victim_tid);
	if (submit)
		__push_event(dbg, victim_tid, EVENT_SUSPEND, evt_data);

	return 0;
}

/**
 * lock_all_threads - Locks all victim threads
 * @debugger_tgid: TGID of the debugger holding the lock
 * @victim_tgid:   TGID of the victim process
 * @reason:        Reason for installing the lock
 *
 * Returns 0 on success.
 * Returns -ENOMEM if allocation fails.
 * Returns -ESRCH  if the task could not be found.
 * Returns any error from __debugger and __victim.
 */
static int __lock_all_threads(pid_t debugger_tgid, pid_t victim_tgid, int reason)
{
	struct task_struct *task;
	struct task_struct *thread;
	struct debugger    *dbg;
	struct thread_lock *lck;
	struct victim      *vct;
	union event_data    evt_data;
	bool                suspend;
	bool                submit;
	TRACE("lock_all_threads(%d, %d)\n", debugger_tgid, victim_tgid);

	evt_data.suspension_reason = reason;

	rcu_read_lock();
	task = pid_task(find_vpid(victim_tgid), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return(-ESRCH, rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();


	/* Get the debugger entry corresponding to the given TGID */
	dbg = __debugger(debugger_tgid);
	if (IS_ERR(dbg))
		return PTR_ERR(dbg);

	/* Get the victim entry from the given TID */
	vct = __victim(victim_tgid);
	if (IS_ERR(vct))
		return PTR_ERR(vct);

	/* Iterate over the task's threads */
	thread = task;
	rcu_read_lock();
	do {
		if (__is_exiting(thread->pid))
			continue;

		/* Check that the lock does not already exist and allocate a new one */
		FIND_LIST_ENTRY(lck, &dbg->locks, debugger_node, lck->victim_tid == thread->pid);
		if (lck != NULL)
			continue;
		FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->victim_tid == thread->pid);
		suspend = (lck == NULL);
		FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->victim_tid == thread->pid && lck->event_submitted);
		submit = (reason != SUSPEND_EXPLICIT) || (!suspend && (lck == NULL));
		if (!ALLOC_PTR(lck))
			cleanup_and_return(-ENOMEM, rcu_read_unlock());

		/* Add the lock to both lists and set its members. */
		list_add_tail(&lck->victim_node, &vct->locks);
		list_add_tail(&lck->debugger_node, &dbg->locks);
		lck->victim_tid = thread->pid;
		lck->debugger_tgid = debugger_tgid;
		lck->reason = reason;
		lck->event_submitted = submit;

		/* Suspend the victim task */
		if (suspend)
			suspend_thread(thread->pid);
		if (submit)
			__push_event(dbg, thread->pid, EVENT_SUSPEND, evt_data);
	} while_each_thread(task, thread);
	rcu_read_unlock();

	return 0;
}

/**
 * unlock_thread - Removes a thread lock
 * @debugger_tgid: TGID of the debugger holding the lock
 * @victim_tid:    TID of the victim thread
 *
 * Returns 0 on success.
 * Returns -EAGAIN if there is no such lock.
 * Returns -ENOMEM if allocation fails.
 * Returns any error from __get_debugger or __get_victim.
 */
static int __unlock_thread(pid_t debugger_tgid, pid_t victim_tid)
{
	struct debugger    *dbg;
	struct victim      *vct;
	struct thread_lock *lck;
	TRACE("unlock_thread(%d, %d)\n", debugger_tgid, victim_tid);

	/* Get the victim entry */
	vct = __get_victim(victim_tid);
	if (vct == NULL)
		return -EAGAIN;
	if (IS_ERR(vct))
		return PTR_ERR(vct);

	/* Get the debugger corresponding to that TGID */
	dbg = __get_debugger(debugger_tgid);
	if (dbg == NULL)
		return -EAGAIN;
	if (IS_ERR(dbg))
		return PTR_ERR(dbg);

	/* Find the lock */
	FIND_LIST_ENTRY(lck, &dbg->locks, debugger_node, lck->victim_tid == victim_tid);
	if (lck == NULL)
		return -EAGAIN;

	/* Remove it from both lists and free the entry */
	list_del(&lck->victim_node);
	list_del(&lck->debugger_node);
	kfree(lck);

	/* If this is the only lock of that TID, continue that thread */
	FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->victim_tid == victim_tid);
	if (lck == NULL)
		wake_up_thread(victim_tid);

	return 0;
}

/**
 * unlock_all_threads - Removes all thread locks held by a debugger for a victim TGID
 * @debugger_tgid: TGID of the debugger holding the locks
 * @victim_tgid:   TGID of the victim process
 *
 * Returns 0 on success.
 * Returns -ENOMEM on allocation failure.
 * Returns any error from __get_debugger or __get_victim.
 */
static int __unlock_all_threads(pid_t debugger_tgid, pid_t victim_tgid)
{
	struct debugger    *dbg;
	struct victim      *vct;
	struct thread_lock *it;
	struct thread_lock *lck;
	struct thread_lock *duplicate;

	struct list_head    removed;
	TRACE("unlock_all_threads(%d, %d)\n", debugger_tgid, victim_tgid);
	INIT_LIST_HEAD(&removed);

	/* Get the debugger corresponding to that TGID */
	dbg = __get_debugger(debugger_tgid);
	if (dbg == NULL)
		return 0;
	if (IS_ERR(dbg))
		return PTR_ERR(dbg);

	/* Get the victim entry */
	vct = __get_victim(victim_tgid);
	if (dbg == NULL)
		return 0;
	if (IS_ERR(vct))
		return PTR_ERR(vct);

	/* Move all matching locks to the "removed" list */
	list_for_each_entry_safe(lck, it, &vct->locks, victim_node) {
		if (lck->debugger_tgid == debugger_tgid) {
			list_del(&lck->victim_node);
			list_del(&lck->debugger_node);
			list_add_tail(&lck->victim_node, &removed);
		}
	}

	/* Restart threads that are fully unlocked */
	list_for_each_entry_safe(lck, it, &removed, victim_node) {
		FIND_LIST_ENTRY(duplicate, &vct->locks, victim_node, duplicate->victim_tid == lck->victim_tid);
		if (duplicate == NULL)
			wake_up_thread(lck->victim_tid);
		list_del(&lck->victim_node);
		kfree(lck);
	}

	return 0;
}



/* Single-step functionality */

/**
 * install_step_listener - Installs a single-step listener and enables stepping for a thread
 * @debugger_tgid: TGID of the debugger
 * @victim_tid:    TID of the victim
 *
 * Returns 0 on success.
 * Returns -ENOTSUPP if the architecture does not support single-stepping.
 * Returns -EOWNERDEAD if the victim is currently exiting.
 * Returns -ESRCH if the target thread does not exist
 * Returns -EEXIST if the single-step listener is already installed.
 * Returns -ENOMEM if allocation fails.
 * Returns any error from __victim.
 */
static int install_step_listener(pid_t debugger_tgid, pid_t victim_tid)
{
	struct victim      *vct;
	struct single_step *stp;
	struct task_struct *task;
	TRACE("install_step_listener(%d, %d)\n", debugger_tgid, victim_tid);

	/* Check for feature support */
	if (!arch_has_single_step())
		return -ENOTSUPP;

	mutex_lock(&data_mutex);

	/* Get the victim */
	vct = __victim(victim_tid);
	if (IS_ERR(vct))
		cleanup_and_return(PTR_ERR(vct), mutex_unlock(&data_mutex));
	if (__is_exiting(victim_tid))
		cleanup_and_return(-EOWNERDEAD, mutex_unlock(&data_mutex));

	/* Skip if stepping is already enabled */
	FIND_LIST_ENTRY(stp, &vct->step_listeners, node, stp->victim_tid == victim_tid && stp->debugger_tgid == debugger_tgid);
	if (stp != NULL)
		cleanup_and_return(-EEXIST, mutex_unlock(&data_mutex));

	/* Enable single-stepping on the thread */
	FIND_LIST_ENTRY(stp, &vct->step_listeners, node, stp->victim_tid == victim_tid);
	if (stp == NULL) {
		rcu_read_lock();
		task = pid_task(find_vpid(victim_tid), PIDTYPE_PID);
		if (task == NULL)
			cleanup_and_return(-ESRCH, rcu_read_unlock(), mutex_unlock(&data_mutex));
		get_task_struct(task);
		rcu_read_unlock();

		ks_user_enable_single_step(task);

		put_task_struct(task);
	}

	/* Install the listener */
	if (!ALLOC_PTR(stp))
		cleanup_and_return(-ENOMEM, mutex_unlock(&data_mutex));

	stp->victim_tid = victim_tid;
	stp->debugger_tgid = debugger_tgid;
	list_add_tail(&stp->node, &vct->step_listeners);

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * remove_step_listener - Removes a single-step listener and potentially disables stepping for a thread
 * @debugger_tgid: TGID of the debugger
 * @victim_tid:    TID of the victim
 *
 * Returns 0 on success.
 * Returns -ENOENT if the target step listener does not exist.
 * Returns -ESRCH if the target thread does not exist.
 * Returns -EOWNERDEAD if the victim is currently exiting.
 * Returns any error from __get_victim.
 */
static int remove_step_listener(pid_t debugger_tgid, pid_t victim_tid)
{
	struct victim      *vct;
	struct single_step *stp;
	struct task_struct *task;
	TRACE("remove_step_listener(%d, %d)\n", debugger_tgid, victim_tid);

	mutex_lock(&data_mutex);

	/* Get the victim */
	vct = __get_victim(victim_tid);
	if (vct == NULL)
		cleanup_and_return(-ENOENT, mutex_unlock(&data_mutex));
	if (IS_ERR(vct))
		cleanup_and_return(PTR_ERR(vct), mutex_unlock(&data_mutex));
	if (__is_exiting(victim_tid))
		cleanup_and_return(-EOWNERDEAD, mutex_unlock(&data_mutex));

	/* Find the listener */
	FIND_LIST_ENTRY(stp, &vct->step_listeners, node, stp->victim_tid == victim_tid && stp->debugger_tgid == debugger_tgid);
	if (stp == NULL)
		cleanup_and_return(-ENOENT, mutex_unlock(&data_mutex));

	/* Remove the listener */
	list_del(&stp->node);
	kfree(stp);

	/* Check if others are still single-stepping this thread */
	FIND_LIST_ENTRY(stp, &vct->step_listeners, node, stp->victim_tid == victim_tid);
	if (stp == NULL) {
		/* Disable stepping */
		rcu_read_lock();
		task = pid_task(find_vpid(victim_tid), PIDTYPE_PID);
		if (task == NULL)
			cleanup_and_return(-ESRCH, rcu_read_unlock(), mutex_unlock(&data_mutex));
		get_task_struct(task);
		rcu_read_unlock();

		ks_user_disable_single_step(task);

		put_task_struct(task);
	}

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * handle_get_signal - Intercepts get_signal, before the signal is delivered.
 * We use this to suspend single-stepping victims 'just in time'.
 * @probe: The kretprobe_instance at get_signal
 * @regs:  The current register set
 */
int handle_get_signal(struct kretprobe_instance *probe, struct pt_regs *regs)
{
	int                 signr;
	sigset_t            mask;
	siginfo_t           info;
	struct victim      *vct;
	struct single_step *stp;

	TRACE("handle_get_signal(tid: %d)\n", current->pid);

	mutex_lock(&data_mutex);

	/* Get victim */
	vct = __get_victim(current->tgid);
	if (vct == NULL)
		cleanup_and_return(0, mutex_unlock(&data_mutex));
	if (IS_ERR(vct))
		cleanup_and_return(0, mutex_unlock(&data_mutex));

	/* Check if this thread should be single-stepping */
	FIND_LIST_ENTRY(stp, &vct->step_listeners, node, stp->victim_tid == current->pid);
	if (stp == NULL)
		cleanup_and_return(0, mutex_unlock(&data_mutex));

	/* We *are* single-stepping - intercept any SIGTRAP */

	spin_lock_irq(&current->sighand->siglock);

	sigfillset(&mask);
	sigdelset(&mask, SIGTRAP);
	signr = ks_dequeue_signal(current, &mask, &info);

	spin_unlock_irq(&current->sighand->siglock);

	if (signr != SIGTRAP)
		cleanup_and_return(0, mutex_unlock(&data_mutex));

	TRACE("Captured SIGTRAP - stepping %d\n", current->pid);

	/* Found a SIGTRAP - check signal info */
	TRACE("SIGTRAP info: si_signo=%d si_code=%d si_errno=%d si_addr=%p\n", info.si_signo, info.si_code, info.si_errno, info.si_addr);

	/* Lock the thread for each of the listening debuggers */
	list_for_each_entry(stp, &vct->step_listeners, node) {
		if (stp->victim_tid == current->pid) {
			__lock_thread(stp->debugger_tgid, current->pid, SUSPEND_ON_SINGLE_STEP);
			wake_up_thread(stp->debugger_tgid);
		}
	}

	/* Suspend until unlock */
	__suspend_loop();

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * handle_get_signal - Intercepts get_signal before it returns.
 * We use this to clean up the mess that handle_signal left behind.
 * @probe: The kretprobe_instance at get_signal
 * @regs:  The current register set
 */
int handle_get_signal_return(struct kretprobe_instance *probe, struct pt_regs *regs)
{
	mutex_lock(&data_mutex);
	__restore_sigactions();
	mutex_unlock(&data_mutex);
	return 0;
}



/* Signal manipulation */

/**
 * cancel_signal - Removes a queued signal from the specified thread
 * @debugger_tgid: TGID of the debugger making the request
 * @victim_tid: TID of the victim
 *
 * This only has an effect if the thread is currently suspended by the debugger
 * in handle_signal. Then, it cancels that specific signal.
 *
 * You may not be able to cancel fatal signals or SIGSTOP's special effects;
 * these happen before we even know about the signal.
 *
 * Returns any error from __get_victim.
 * Returns -ENOMEM on allocation failure.
 * Returns -EAGAIN if the thread is not suspended on a signal.
 * Returns -EOWNERDEAD if the thread is currently exiting.
 * Returns 0 on success.
 */
static int cancel_signal(pid_t debugger_tgid, pid_t victim_tid)
{
	struct victim       *vct;
	struct thread_lock  *lck;
	struct cancellation *cancel;

	TRACE("cancel_signal(%d, %d)\n", debugger_tgid, victim_tid);

	mutex_lock(&data_mutex);

	if (__is_exiting(victim_tid))
		return -EOWNERDEAD;

	/* Get victim */
	vct = __get_victim(victim_tid);
	if (IS_ERR(vct))
		cleanup_and_return(PTR_ERR(vct), mutex_unlock(&data_mutex));
	if (vct == NULL)
		cleanup_and_return(-EAGAIN, mutex_unlock(&data_mutex));

	/* Check that the thread is locked with SUSPEND_ON_SIGNAL */
	FIND_LIST_ENTRY(lck, &vct->locks, victim_node, lck->debugger_tgid == debugger_tgid && lck->reason == SUSPEND_ON_SIGNAL);
	if (lck == NULL)
		cleanup_and_return(-EAGAIN, mutex_unlock(&data_mutex));

	/* Check if the signal is already canceled */
	hash_for_each_possible(signal_canceled, cancel, node, HASH_ID(victim_tid))
		if (cancel->tid == victim_tid)
			cleanup_and_return(0, mutex_unlock(&data_mutex));

	/* Cancel the signal */
	if (!ALLOC_PTR(cancel))
		cleanup_and_return(-ENOMEM, mutex_unlock(&data_mutex));
	cancel->tid = victim_tid;
	cancel->state = CANCELLATION_PENDING;
	hash_add(signal_canceled, &cancel->node, HASH_ID(victim_tid));

	mutex_unlock(&data_mutex);
	return 0;
}



/* Breakpoints */

/**
 * install_breakpoint - Installs a breakpoint for the given debugger at the specified victim address
 * @debugger_tgid: TGID of the debugger
 * @victim_tid:    TID (or TGID) of the victim
 * @addr:          Address of the breakpoint in the victim's address space
 *
 * Returns -ENOMEM if allocation fails.
 * Returns -EEXIST if the breakpoint already exists.
 * Returns -EOWNERDEAD if the victim is currently exiting.
 * Returns any error from __debugger or __breakpoint.
 */
static int install_breakpoint(pid_t debugger_tgid, pid_t victim_tid, addr_t addr)
{
	struct debugger        *dbg;
	struct breakpoint      *bp;
	struct attached_config *cfg;
	TRACE("install_breakpoint(%d, %d, %lx)\n", debugger_tgid, victim_tid, addr);

	mutex_lock(&data_mutex);

	/* Get debugger  */
	dbg = __debugger(debugger_tgid);
	if (IS_ERR(dbg))
		cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

	if (__is_exiting(victim_tid))
		cleanup_and_return(-EOWNERDEAD, mutex_unlock(&data_mutex));

	/* Create breakpoint */
	bp = __breakpoint(victim_tid, addr);
	if (IS_ERR(bp))
		cleanup_and_return(PTR_ERR(bp), mutex_unlock(&data_mutex));
	if (bp->state == BP_STATE_DEAD)
		smp_store_mb(bp->state, BP_STATE_ACTIVE);

	/* Check if the debugger is already attached to this breakpoint */
	FIND_LIST_ENTRY(cfg, &bp->attached, breakpoint_node, cfg->debugger_tgid == debugger_tgid);
	if (cfg != NULL)
		cleanup_and_return(-EEXIST, mutex_unlock(&data_mutex));

	/* Create the new attached config */
	if (!ALLOC_PTR(cfg))
		cleanup_and_return(-ENOMEM, mutex_unlock(&data_mutex));

	list_add_tail(&cfg->breakpoint_node, &bp->attached);
	list_add_tail(&cfg->debugger_node, &dbg->breakpoints);
	cfg->breakpoint_ref = bp;
	cfg->debugger_tgid = debugger_tgid;

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * remove_breakpoint - Removes a breakpoint for the given debugger at the specified victim address
 * @debugger_tgid: TGID of the debugger
 * @victim_tid:    TID (or TGID) of the victim
 * @addr:          Address of the breakpoint in the victim's address space
 *
 * Returns -ENOMEM on allocation failure.
 * Returns -ENOENT if the breakpoint does not exist for this debugger.
 * Returns any error from __debugger or __breakpoint.
 */
static int remove_breakpoint(pid_t debugger_tgid, pid_t victim_tid, addr_t addr)
{
	struct debugger        *dbg;
	struct breakpoint      *bp;
	struct attached_config *cfg;
	struct victim          *vct;
	TRACE("remove_breakpoint(%d, %d, %lx)\n", debugger_tgid, victim_tid, addr);

	mutex_lock(&data_mutex);

	/* Get debugger and breakpoint */
	dbg = __get_debugger(debugger_tgid);
	if (dbg == NULL)
		cleanup_and_return(-ENOENT, mutex_unlock(&data_mutex));
	if (IS_ERR(dbg))
		cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

	bp = __breakpoint(victim_tid, addr);
	if (IS_ERR(bp))
		cleanup_and_return(PTR_ERR(bp), mutex_unlock(&data_mutex));

	/* Find the config entry */
	FIND_LIST_ENTRY(cfg, &bp->attached, breakpoint_node, cfg->debugger_tgid == debugger_tgid);
	if (cfg == NULL)
		cleanup_and_return(-ENOENT, mutex_unlock(&data_mutex));

	/* Delete the config entry */
	list_del(&cfg->breakpoint_node);
	list_del(&cfg->debugger_node);
	kfree(cfg);

	/* Delete unused breakpoints, victims, and debuggers */
	if (list_empty(&bp->attached)) {
		__delete_breakpoint(bp);

		vct = __get_victim(victim_tid);
		if (!IS_ERR(vct) && vct != NULL && list_empty(&vct->breakpoints) && list_empty(&vct->locks) && list_empty(&vct->step_listeners))
			__delete_victim(vct);
	}
	if (list_empty(&dbg->breakpoints) && list_empty(&dbg->locks))
		__delete_debugger(dbg);

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * handle_breakpoint - Handles a breakpoint hit
 * @self: The uprobe consumer that caused the breakpoint hit
 * @regs: The current ptrace register set
 */
static int handle_breakpoint(struct uprobe_consumer *self, struct pt_regs *regs)
{
	struct victim          *vct;
	struct breakpoint      *bp;
	struct attached_config *cfg;
	TRACE("handle_breakpoint(%d, %d, %lx)\n", current->tgid, current->pid, instruction_pointer(regs));

	mutex_lock(&data_mutex);

	/* Get the victim */
	vct = __get_victim(current->tgid);
	if (IS_ERR(vct) || vct == NULL || list_empty(&vct->breakpoints))
		cleanup_and_return(0, mutex_unlock(&data_mutex));

	/* Find the breakpoint */
	FIND_LIST_ENTRY(bp, &vct->breakpoints, node, bp->address == instruction_pointer(regs));
	if (bp == NULL || list_empty(&bp->attached) || bp->state == BP_STATE_DEAD)
		cleanup_and_return(0, mutex_unlock(&data_mutex));

	/* Lock the thread for each of the debuggers */
	atomic_inc(&bp->counter);
	list_for_each_entry(cfg, &bp->attached, breakpoint_node) {
		__lock_thread(cfg->debugger_tgid, current->pid, SUSPEND_ON_BREAK);
		wake_up_thread(cfg->debugger_tgid);
	}

	__suspend_loop();

	/* Check if the breakpoint is dead and was just waiting on us with removal */
	if (atomic_dec_and_test(&bp->counter))
		if (READ_ONCE(bp->state) == BP_STATE_DEAD)
			__delete_breakpoint(bp);

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * handle_suspension_breakpoint - Suspends the current thread upon hitting a temporary breakpoint
 * @self: The uprobe consumer that caused the breakpoint hit
 * @regs: The current ptrace register set
 *
 * See suspend_thread for context.
 */
static int handle_suspension_breakpoint(struct uprobe_consumer *self, struct pt_regs *regs)
{
	struct breakpoint      *bp;
	struct victim          *vct;
	struct thread_lock     *lck;
	struct debugger        *dbg;
	struct dead_breakpoint *deferred;
	union event_data        evt_data;

	evt_data.suspension_reason = SUSPEND_EXPLICIT;

	/* Grabbing the breakpoint using container_of leads to crashes, so use FIND_LIST_ENTRY instead */
	mutex_lock(&suspension_mutex);

	FIND_LIST_ENTRY(bp, &pending_suspensions, node, bp->target == current->pid && bp->address == instruction_pointer(regs));
	if (bp == NULL)
		cleanup_and_return(0, mutex_unlock(&suspension_mutex));
	TRACE("actual handle_suspension_breakpoint(%p <%d, %lx> for <%d, %lx>)\n", bp, current->pid, instruction_pointer(regs), bp->target, bp->address);
	list_del(&bp->node);

	mutex_unlock(&suspension_mutex);

	/* Send suspension event to all locks */
	mutex_lock(&data_mutex);

	vct = __victim(current->tgid);
	if (IS_ERR(vct))
		cleanup_and_return(0, mutex_unlock(&data_mutex));

	list_for_each_entry(lck, &vct->locks, victim_node) {
		dbg = __get_debugger(lck->debugger_tgid);
		if (IS_ERR(dbg) || dbg == NULL)
			continue;
		__push_event(dbg, current->pid, EVENT_SUSPEND, evt_data);
	}

	__suspend_loop();

	mutex_unlock(&data_mutex);

	/* Remove the temporary breakpoint */
	TRACE("suspension done for %d\n", current->pid);
	if (!ALLOC_PTR(deferred)) {
		printk(KERN_ERR "Could not defer cleanup for suspension breakpoint at TID %d, address %lx\n", bp->target, bp->address);
		return UPROBE_HANDLER_REMOVE; /* Try to recover */
	}

	INIT_WORK(&deferred->work, delete_dead_breakpoint);
	deferred->bp = bp;
	queue_work(deferred_queue, &deferred->work);

	return 0;
}

static int read_auxv(pid_t tid, size_t size, char __user *uptr)
{
	struct task_struct *task;
	struct mm_struct   *mm;

	//TRACE("read_auxv(%d, %lu, %p)\n", tid, size, uptr);

	/* Get the memory mapping for this process */
	rcu_read_lock();
	task = pid_task(find_vpid(tid), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return(-ESRCH, rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	mm = get_task_mm(task);
	if (mm == NULL)
		cleanup_and_return(-EACCES, put_task_struct(task));

	/* Copy contents of auxv to userspace if the buffer is large enough) */
	if (size < AT_VECTOR_SIZE * sizeof(void *))
		cleanup_and_return(-EINVAL, mmput(mm), put_task_struct(task));

	if ((copy_to_user(uptr, mm->saved_auxv, AT_VECTOR_SIZE * sizeof(void *))) != 0)
		cleanup_and_return(-EFAULT, mmput(mm), put_task_struct(task));

	mmput(mm);
	put_task_struct(task);

	return AT_VECTOR_SIZE * sizeof(void *);
}


/* Copy operations */

typedef int copy_direction_t;
#define COPY_TO_USERSPACE   0
#define COPY_FROM_USERSPACE 1

/**
 * copy_memory - Copies memory from and to userspace
 * @tid:  TID (or TGID) of the target thread/process
 * @addr: Target (virtual) address to read from
 * @size: Size of the target buffer or the amount of data to be read
 * @uptr: Pointer to a userspace buffer
 * @dir:  Whether to copy data *to* or *from* userspace
 *
 * Returns the number of bytes copied.
 * Returns -ESRCH  if the thread does not exist.
 * Returns -EACCES if there is no memory to access (e.g. the task is a kernel task).
 * Returns -EFAULT if the userspace buffer is not accessible.
 * Returns -EACCES if the target address is not accessible.
 */
static int copy_memory(pid_t tid, addr_t addr, size_t size, char __user *uptr, copy_direction_t dir)
{
	struct task_struct *task;
	struct mm_struct   *mm;
	size_t              copied;
	size_t              current_length;

	//TRACE("copy_memory(%d, %lx, %lu, %p, %d)\n", tid, addr, size, uptr, dir);

	/* Get the memory mapping for this process */
	rcu_read_lock();
	task = pid_task(find_vpid(tid), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return(-ESRCH, rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	mm = get_task_mm(task);
	if (mm == NULL)
		cleanup_and_return(-EACCES, put_task_struct(task));

	/* Copy data via access_process_vm. __access_remote_vm would be more efficient, but isn't exported. */
	for (copied = 0; copied < size;) {
		char buffer[128];
		current_length = ((size - copied) > sizeof(buffer)) ? sizeof(buffer) : (size - copied);

		switch (dir) {
		case COPY_TO_USERSPACE:
			current_length = access_process_vm(task, addr + copied, buffer, current_length, FOLL_FORCE);
			if (current_length == 0)
				cleanup_and_return(-EACCES, mmput(mm), put_task_struct(task));
			if (copy_to_user(uptr + copied, buffer, current_length) != 0)
				cleanup_and_return(-EFAULT, mmput(mm), put_task_struct(task));
			copied += current_length;
			break;
		case COPY_FROM_USERSPACE:
			if (copy_from_user(buffer, uptr + copied, current_length) != 0)
				cleanup_and_return(-EFAULT, mmput(mm), put_task_struct(task));
			current_length = access_process_vm(task, addr + copied, buffer, current_length, FOLL_FORCE | FOLL_WRITE);
			if (current_length == 0)
				cleanup_and_return(-EACCES, mmput(mm), put_task_struct(task));
			copied += current_length;
			break;
		default:
			printk(KERN_ERR "Invalid direction in copy_memory\n");
			cleanup_and_return(-EINVAL, mmput(mm), put_task_struct(task));
		}
	}

	mmput(mm);
	put_task_struct(task);

	return copied;
}

/**
 * copy_registers - Copies registers to userspace
 * @tid:  TID of the target thread
 * @type: Request type. Should be NT_PRSTATUS (= 1) by default.
 * @uptr: Pointer to a userspace buffer containing the register data
 * @dir:  Whether to copy data *to* or *from* userspace
 *
 * Returns -ESRCH if the thread does not exist.
 * Returns -EINVAL if an invalid request type is provided.
 * Returns -EOPNOTSUPP if getting the register set is not supported
 * Returns -EFAULT if the userspace buffer is inaccessible
 */
static int copy_registers(pid_t tid, int type, size_t __user *size, char __user *uptr, copy_direction_t dir)
{
	struct task_struct            *task;
	const struct user_regset_view *view;
	const struct user_regset      *regset;
	unsigned int                   regset_index;
	size_t                         actual_size;
	size_t                         regset_size;
	int                            copied;
	TRACE("copy_registers(%d, %d, %p, %p, %d)\n", tid, type, size, uptr, dir);

	/* Get the memory mapping for this process */
	rcu_read_lock();
	task = pid_task(find_vpid(tid), PIDTYPE_PID);
	if (task == NULL)
		cleanup_and_return(-ESRCH, rcu_read_unlock());
	get_task_struct(task);
	rcu_read_unlock();

	/* Get the proper regset */
	view = task_user_regset_view(task);
	for (regset_index = 0, regset = NULL; regset_index < view->n; ++regset_index) {
		if (view->regsets[regset_index].core_note_type == type) {
			regset = &view->regsets[regset_index];
			break;
		}
	}
	if (regset == NULL)
		cleanup_and_return(-EINVAL, put_task_struct(task));

	/* Determine and store the size of the copied data */
	regset_size = regset->n * regset->size;
	if (copy_from_user(&actual_size, size, sizeof(size_t)) != 0)
		cleanup_and_return(-EFAULT, put_task_struct(task));
	if (copy_to_user(size, &regset_size, sizeof(size_t)) != 0)
		cleanup_and_return(-EFAULT, put_task_struct(task));
	TRACE("copy_registers<%d> : regset size is %lu, available space is %lu\n", type, regset_size, actual_size);
	if (actual_size > regset_size)
		actual_size = regset_size;

	/* Copy data */
	switch (dir) {
	case COPY_TO_USERSPACE:
		copied = copy_regset_to_user(task, view, regset_index, 0, actual_size, uptr);
		break;
	case COPY_FROM_USERSPACE:
		copied = copy_regset_from_user(task, view, regset_index, 0, actual_size, uptr);
		break;
	default:
		printk(KERN_ERR "Invalid direction in copy_registers\n");
		cleanup_and_return(-EINVAL, put_task_struct(task));
	}

	put_task_struct(task);
	return copied;
}

/**
 * read_status - Copies the debugger's list of suspended threads to userspace
 * @tgid: TGID of the debugger
 * @uptr: Pointer to the kernel copy of the ioctl_enumeration
 *
 * Returns 0 on success.
 * Returns -EFAULT if the userspace buffer is inaccessible
 * Returns any error from __debugger.
 */
static int read_status(pid_t tgid, struct ioctl_enumeration *uptr)
{
	struct debugger    *dbg;
	struct thread_lock *lck;
	pid_t __user       *buf;
	size_t              actual_size;
	size_t              counter;
	size_t              written;
	TRACE("read_status(%d, %p)\n", tgid, uptr);

	buf = (pid_t __user *) uptr->buffer;
	actual_size = uptr->size;

	mutex_lock(&data_mutex);

	/* Get the debugger corresponding to that TGID */
	dbg = __debugger(tgid);
	if (IS_ERR(dbg))
		cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

	/* Iterate over all locks */
	counter = written = 0;
	list_for_each_entry(lck, &dbg->locks, debugger_node)
		if (counter++ < actual_size)
			if (copy_to_user(buf + written++, &lck->victim_tid, sizeof(pid_t)) != 0)
				cleanup_and_return(-EFAULT, mutex_unlock(&data_mutex));

	uptr->size = written;
	uptr->available = counter;

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * enumerate_threads - Copies the PIDs of a process's threads to userspace
 * @uptr: Pointer to the kernel copy of the ioctl_enumeration
 *
 * Returns 0 on success.
 * Returns -EFAULT if the userspace buffer is inaccessible
 * Returns -ESRCH if the process does not exist.
 */
static int enumerate_threads(struct ioctl_enumeration *uptr)
{
	struct task_struct *task;
	struct task_struct *thread;
	pid_t               target;
	pid_t __user       *buf;
	size_t              actual_size;
	size_t              counter;
	size_t              written;
	TRACE("enumerate_threads(%d, %p)\n", uptr->target, uptr);

	target = uptr->target;
	buf = (pid_t __user *) uptr->buffer;
	actual_size = uptr->size;

	target = tgid_from_tid(target);
	if (target == -ESRCH)
		return -ESRCH;

	counter = written = 0;

	rcu_read_lock();
	task = pid_task(find_vpid(target), PIDTYPE_PID);
	if (task != NULL) {
		thread = task;
		do {
			if (counter++ < actual_size)
				if (copy_to_user(buf + written++, &thread->pid, sizeof(pid_t)) != 0)
					cleanup_and_return(-EFAULT, rcu_read_unlock());
		} while_each_thread(task, thread);
	}
	rcu_read_unlock();

	uptr->size = written;
	uptr->available = counter;

	return 0;
}

/**
 * suspend_reason - Copies the suspension reason of a thread to userspace
 * @debugger_tgid: TGID of the debugger making the request
 * @uptr:          Pointer to the kernel copy of the ioctl_flag
 *
 * Returns 0 on success.
 * Returns -EFAULT if the userspace buffer is inaccessible
 * Returns any error from __debugger.
 */
static int suspend_reason(pid_t debugger_tgid, struct ioctl_flag *uptr)
{
	struct debugger    *dbg;
	struct thread_lock *lck;
	pid_t               target;
	int                 reason;
	TRACE("suspend_reason(%d, %p)\n", debugger_tgid, uptr);

	target = uptr->target;

	mutex_lock(&data_mutex);

	/* Get the debugger corresponding to that TGID */
	dbg = __debugger(debugger_tgid);
	if (IS_ERR(dbg))
		cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

	/* Find the lock */
	FIND_LIST_ENTRY(lck, &dbg->locks, debugger_node, lck->victim_tid == target);
	reason = lck ? lck->reason : NOT_SUSPENDED;

	uptr->value = reason;

	mutex_unlock(&data_mutex);
	return 0;
}



/* Event subscriptions */

/**
 * set_event_mask - Sets the event mask for a debugger and victim.
 * @debugger_tgid: TGID of the debugger making the request
 * @victim_tid:    TID or TGID of the victim for which the event mask should be set
 * @event_mask:    The event mask
 *
 * Returns 0 on success.
 * Returns -ENOMEM on allocation failure.
 * Returns any error from __victim.
 */
int set_event_mask(pid_t debugger_tgid, pid_t victim_tid, int event_mask)
{
	struct victim         *vct;
	struct debugger       *dbg;
	struct event_listener *lst;
	TRACE("set_event_mask(debugger = %d, victim = %d, mask = %x)\n", debugger_tgid, victim_tid, event_mask);

	mutex_lock(&data_mutex);

	/* Get the victim */
	vct = __victim(victim_tid);
	if (IS_ERR(vct))
		cleanup_and_return(PTR_ERR(vct), mutex_unlock(&data_mutex));

	/* Allocate the debugger if it does not exist yet */
	dbg = __debugger(debugger_tgid);
	if (IS_ERR(dbg))
		cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

	/* Find the event mask entry */
	FIND_LIST_ENTRY(lst, &vct->event_listeners, node, lst->debugger_tgid == debugger_tgid);
	if (lst == NULL) {
		if (!ALLOC_PTR(lst))
			cleanup_and_return(-ENOMEM, mutex_unlock(&data_mutex));
		lst->debugger_tgid = debugger_tgid;
		lst->event_mask = event_mask;
		list_add_tail(&lst->node, &vct->event_listeners);
	} else {
		lst->event_mask = event_mask;
	}

	mutex_unlock(&data_mutex);
	return 0;
}

/**
 * __push_event - Pushes an event into the debugger's event queue
 * @debugger:   The debugger
 * @victim_tid: TID of the thread generating the event
 * @event_id:   ID of the event to be pushed
 * @data:       Additional event data
 */
void __push_event(struct debugger *dbg, pid_t victim_tid, int event_id, union event_data data)
{
	struct event *evt;

	TRACE("__push_event(debugger: %d, victim: %d, event: %d)\n", dbg->tgid, victim_tid, event_id);

	if (!ALLOC_PTR(evt))
		cleanup_and_return_void(mutex_unlock(&data_mutex));
	evt->victim_tid = victim_tid;
	evt->event_id = event_id;
	evt->data = data;
	list_add_tail(&evt->node, &dbg->event_queue);

	wake_up_thread(dbg->tgid);
}

/**
 * __dump_event_queue - Dumps the event queue to the user
 * @filter:        Only pass on events for this victim TID. If 0, pass all events
 * @debugger_tgid: The debugger in question
 * @uptr:          Pointer to a kernel copy of the ioctl_enumeration struct
 *
 * Returns 0 on success.
 * Returns -EFAULT if the userspace buffer is inaccessible.
 * Returns any error from __debugger.
 */
int __dump_event_queue(pid_t filter, pid_t debugger_tgid, struct ioctl_enumeration *uptr)
{
	struct debugger           *dbg;
	struct ioctl_event __user *buf;
	struct ioctl_event         ioctl_evt;
	struct event               *evt;
	struct event               *evt_it;
	size_t                     actual_size;
	size_t                     counter;
	size_t                     written;

	TRACE("__dump_event_queue(filter: %d, debugger_tgid: %d, uptr: %p)\n", filter, debugger_tgid, (void *) uptr);

	buf = (struct ioctl_event __user *) uptr->buffer;
	actual_size = uptr->size;

	dbg = __debugger(debugger_tgid);
	if (IS_ERR(dbg))
		return PTR_ERR(dbg);

	counter = written = 0;

	list_for_each_entry_safe(evt, evt_it, &dbg->event_queue, node) {
		if (!filter || filter == evt->victim_tid) {
			if (counter++ < actual_size) {
				ioctl_evt.event_id = evt->event_id;
				ioctl_evt.victim_tid = evt->victim_tid;
				ioctl_evt.data = evt->data;
				if (copy_to_user(buf + written++, &ioctl_evt, sizeof(struct ioctl_event)) != 0)
					return -EFAULT;
				list_del(&evt->node);
			}
		}
	}

	counter -= written; /* Because we clear the event queue, remove the written elements */

	uptr->size = written;
	uptr->available = counter;

	return 0;
}



/* Communications */

#define IOCTL_CODE '@'

#define IOCTL_CONTINUE           _IOW(IOCTL_CODE,  0, struct ioctl_tid_or_tgid)
#define IOCTL_SUSPEND            _IOW(IOCTL_CODE,  1, struct ioctl_tid_or_tgid)
#define IOCTL_INSTALL_BREAKPOINT _IOW(IOCTL_CODE, 10, struct ioctl_breakpoint_identifier)
#define IOCTL_REMOVE_BREAKPOINT  _IOW(IOCTL_CODE, 11, struct ioctl_breakpoint_identifier)
#define IOCTL_SET_STEP           _IOW(IOCTL_CODE, 20, struct ioctl_flag)
#define IOCTL_SET_EVENT_MASK     _IOW(IOCTL_CODE, 30, struct ioctl_flag)
#define IOCTL_CANCEL_SIGNAL      _IOW(IOCTL_CODE, 40, struct ioctl_tid_or_tgid)

#define IOCTL_WAIT               _IOWR(IOCTL_CODE,  0, struct ioctl_enumeration)
#define IOCTL_WAIT_FOR           _IOWR(IOCTL_CODE,  1, struct ioctl_enumeration)
#define IOCTL_EVENTS             _IOWR(IOCTL_CODE,  2, struct ioctl_enumeration)
#define IOCTL_STATUS             _IOWR(IOCTL_CODE, 10, struct ioctl_enumeration)
#define IOCTL_ENUMERATE_THREADS  _IOWR(IOCTL_CODE, 11, struct ioctl_enumeration)
#define IOCTL_SUSPEND_REASON     _IOWR(IOCTL_CODE, 12, struct ioctl_flag)
#define IOCTL_READ_MEMORY        _IOWR(IOCTL_CODE, 20, struct ioctl_cpy)
#define IOCTL_WRITE_MEMORY       _IOWR(IOCTL_CODE, 21, struct ioctl_cpy)
#define IOCTL_READ_AUXV          _IOWR(IOCTL_CODE, 22, struct ioctl_cpy)
#define IOCTL_READ_REGISTERS     _IOWR(IOCTL_CODE, 30, struct ioctl_cpy)
#define IOCTL_WRITE_REGISTERS    _IOWR(IOCTL_CODE, 31, struct ioctl_cpy)

/**
 * on_ioctl - handles an incoming IOCTL
 * @fp:       file on which the IOCTL was performed
 * @command:  IOCTL command (see macros above)
 * @argument: pointer to additional (userspace) data
 */
static long on_ioctl(struct file *fp, unsigned int command, unsigned long argument)
{
	union ioctl_argument  arg;
	struct debugger      *dbg;
	struct event         *evt;
	int                   result;

	if (READ_ONCE(module_unloading))
		return -ENODEV;

	switch (command) {
	case IOCTL_CONTINUE:
		if (copy_from_user(&arg.arg_id, (void *) argument, sizeof(struct ioctl_tid_or_tgid)) != 0)
			return -EFAULT;
		TRACE("ioctl: continue(%d, %d) from %d\n", arg.arg_id.type, arg.arg_id.id, current->pid);

		if ((result = check_access(arg.arg_id.id)))
			return result;

		mutex_lock(&data_mutex);
		if (arg.arg_id.type == TID) {
			result = __unlock_thread(current->tgid, arg.arg_id.id);
			cleanup_and_return(result, mutex_unlock(&data_mutex));
		} else if (arg.arg_id.type == TGID) {
			result = __unlock_all_threads(current->tgid, arg.arg_id.id);
			cleanup_and_return(result, mutex_unlock(&data_mutex));
		} else {
			printk(KERN_ERR "Invalid ID type %u for IOCTL_CONTINUE from %d\n", (unsigned) arg.arg_id.type, current->pid);
			cleanup_and_return(-EINVAL, mutex_unlock(&data_mutex));
		}

	case IOCTL_SUSPEND:
		if (copy_from_user(&arg.arg_id, (void *) argument, sizeof(struct ioctl_tid_or_tgid)) != 0)
			return -EFAULT;
		TRACE("ioctl: suspend(%d, %d) from %d\n", arg.arg_id.type, arg.arg_id.id, current->pid);

		if ((result = check_access(arg.arg_id.id)))
			return result;

		mutex_lock(&data_mutex);
		if (arg.arg_id.type == TID) {
			result = __lock_thread(current->tgid, arg.arg_id.id, SUSPEND_EXPLICIT);
			cleanup_and_return(result, mutex_unlock(&data_mutex));
		} else if (arg.arg_id.type == TGID) {
			result = __lock_all_threads(current->tgid, arg.arg_id.id, SUSPEND_EXPLICIT);
			cleanup_and_return(result, mutex_unlock(&data_mutex));
		} else {
			printk(KERN_ERR "Invalid ID type %u for IOCTL_SUSPEND from %d\n", (unsigned) arg.arg_id.type, current->pid);
			cleanup_and_return(-EINVAL, mutex_unlock(&data_mutex));
		}

	case IOCTL_INSTALL_BREAKPOINT:
		if (copy_from_user(&arg.arg_breakpoint, (void *) argument, sizeof(struct ioctl_breakpoint_identifier)) != 0)
			return -EFAULT;
		TRACE("ioctl: install_breakpoint(%d, %lx) from %d\n", arg.arg_breakpoint.target, arg.arg_breakpoint.address, current->pid);
		if ((result = check_access(arg.arg_breakpoint.target)))
			return result;
		return install_breakpoint(current->tgid, arg.arg_breakpoint.target, arg.arg_breakpoint.address);

	case IOCTL_REMOVE_BREAKPOINT:
		if (copy_from_user(&arg.arg_breakpoint, (void *) argument, sizeof(struct ioctl_breakpoint_identifier)) != 0)
			return -EFAULT;
		TRACE("ioctl: remove_breakpoint(%d, %lx) from %d\n", arg.arg_breakpoint.target, arg.arg_breakpoint.address, current->pid);
		if ((result = check_access(arg.arg_breakpoint.target)))
			return result;
		return remove_breakpoint(current->tgid, arg.arg_breakpoint.target, arg.arg_breakpoint.address);

	case IOCTL_SET_STEP:
		if (copy_from_user(&arg.arg_flag, (void *) argument, sizeof(struct ioctl_flag)) != 0)
			return -EFAULT;
		TRACE("ioctl: set_step(%d, %d) from %d\n", arg.arg_flag.target, arg.arg_flag.value, current->pid);
		if ((result = check_access(arg.arg_flag.target)))
			return result;
		if (arg.arg_flag.value)
			return install_step_listener(current->tgid, arg.arg_flag.target);
		else
			return remove_step_listener(current->tgid, arg.arg_flag.target);

	case IOCTL_SET_EVENT_MASK:
		if (copy_from_user(&arg.arg_flag, (void *) argument, sizeof(struct ioctl_flag)) != 0)
			return -EFAULT;
		if ((result = check_access(arg.arg_flag.target)))
			return result;
		TRACE("ioctl: set_event_mask(%d, %d) from %d\n", arg.arg_flag.target, arg.arg_flag.value, current->pid);
		return set_event_mask(current->tgid, arg.arg_flag.target, arg.arg_flag.value);

	case IOCTL_CANCEL_SIGNAL:
		if (copy_from_user(&arg.arg_id, (void *) argument, sizeof(struct ioctl_tid_or_tgid)) != 0)
			return -EFAULT;
		TRACE("ioctl: cancel_signal(%d) from %d\n", arg.arg_id.id, current->pid);
		if ((result = check_access(arg.arg_id.id)))
			return result;
		return cancel_signal(current->tgid, arg.arg_id.id);

	case IOCTL_WAIT:
		if (copy_from_user(&arg.arg_enumeration, (void *) argument, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		TRACE("ioctl: wait() from %d\n", current->pid);

		for (;;) {
			/* Check whether to suspend */
			mutex_lock(&data_mutex);
			dbg = __debugger(current->tgid);

			if (IS_ERR(dbg))
				cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

			/* Return events if there are any in the queue */
			if (!list_empty(&dbg->event_queue)) {
				result = __dump_event_queue(0, current->tgid, &arg.arg_enumeration);
				if (copy_to_user((void *) argument, &arg.arg_enumeration, sizeof(struct ioctl_enumeration)) != 0)
					cleanup_and_return(-EFAULT, mutex_unlock(&data_mutex));
				cleanup_and_return(result, mutex_unlock(&data_mutex));
			}
			mutex_unlock(&data_mutex);

			/* Suspend */
			suspend_thread(current->pid);
			schedule();
		}
		return 0;

	case IOCTL_WAIT_FOR:
		if (copy_from_user(&arg.arg_enumeration, (void *) argument, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		TRACE("ioctl: wait_for(%d) from %d\n", arg.arg_enumeration.target, current->pid);

		if ((result = check_access(arg.arg_enumeration.target)))
			return result;

		for (;;) {
			/* Check whether to suspend */
			mutex_lock(&data_mutex);
			dbg = __debugger(current->tgid);

			if (IS_ERR(dbg))
				cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

			/* Return events if there are any in the queue */
			FIND_LIST_ENTRY(evt, &dbg->event_queue, node, evt->victim_tid == arg.arg_enumeration.target);
			if (evt != NULL) {
				result = __dump_event_queue(arg.arg_enumeration.target, current->tgid, &arg.arg_enumeration);
				if (copy_to_user((void *) argument, &arg.arg_enumeration, sizeof(struct ioctl_enumeration)) != 0)
					cleanup_and_return(-EFAULT, mutex_unlock(&data_mutex));
				cleanup_and_return(result, mutex_unlock(&data_mutex));
			}
			mutex_unlock(&data_mutex);

			/* Suspend */
			suspend_thread(current->pid);
			schedule();
		}
		return 0;

	case IOCTL_EVENTS:
		if (copy_from_user(&arg.arg_enumeration, (void *) argument, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		TRACE("ioctl: events() from %d\n", current->pid);

		mutex_lock(&data_mutex);
		dbg = __debugger(current->tgid);

		if (IS_ERR(dbg))
			cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));

		/* Return events if there are any in the queue */
		if (!list_empty(&dbg->event_queue))
			result = __dump_event_queue(arg.arg_enumeration.target, current->tgid, &arg.arg_enumeration);
		else
			result = arg.arg_enumeration.size = arg.arg_enumeration.available = 0;

		if (copy_to_user((void *) argument, &arg.arg_enumeration, sizeof(struct ioctl_enumeration)) != 0)
			cleanup_and_return(-EFAULT, mutex_unlock(&data_mutex));

		mutex_unlock(&data_mutex);
		return result;

	case IOCTL_STATUS:
		if (copy_from_user(&arg.arg_enumeration, (void *) argument, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		TRACE("ioctl: read_status(%d) from %d\n", arg.arg_enumeration.target, current->pid);
		if ((result = check_access(arg.arg_enumeration.target)))
			return result;
		if ((result = read_status(current->tgid, &arg.arg_enumeration)))
			return result;
		if (copy_to_user((void *) argument, &arg.arg_enumeration, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		return result;

	case IOCTL_ENUMERATE_THREADS:
		if (copy_from_user(&arg.arg_enumeration, (void *) argument, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		TRACE("ioctl: enumerate_threads(%d) from %d\n", arg.arg_enumeration.target, current->pid);
		if ((result = check_access(arg.arg_enumeration.target)))
			return result;
		if ((result = enumerate_threads(&arg.arg_enumeration)))
			return result;
		if (copy_to_user((void *) argument, &arg.arg_enumeration, sizeof(struct ioctl_enumeration)) != 0)
			return -EFAULT;
		return result;

	case IOCTL_SUSPEND_REASON:
		if (copy_from_user(&arg.arg_flag, (void *) argument, sizeof(struct ioctl_flag)) != 0)
			return -EFAULT;
		TRACE("ioctl: suspend_reason(%d) from %d\n", arg.arg_flag.target, current->pid);
		if ((result = check_access(arg.arg_flag.target)))
			return result;
		if ((result = suspend_reason(current->tgid, &arg.arg_flag)))
			return result;
		if (copy_to_user((void *) argument, &arg.arg_flag, sizeof(struct ioctl_flag)) != 0)
			return -EFAULT;
		return result;

	case IOCTL_READ_MEMORY:
		if (copy_from_user(&arg.arg_cpy, (void *) argument, sizeof(struct ioctl_cpy)) != 0)
			return -EFAULT;
		//TRACE("ioctl: read_memory(%d, %lx, %ld) from %d\n", arg.arg_cpy.target, arg.arg_cpy.which, arg.arg_cpy.size, current->pid); // This is *very* spammy
		if ((result = check_access(arg.arg_cpy.target)))
			return result;
		return copy_memory(arg.arg_cpy.target, arg.arg_cpy.which, arg.arg_cpy.size, (char __user *) arg.arg_cpy.buffer, COPY_TO_USERSPACE);

	case IOCTL_WRITE_MEMORY:
		if (copy_from_user(&arg.arg_cpy, (void *) argument, sizeof(struct ioctl_cpy)) != 0)
			return -EFAULT;
		TRACE("ioctl: write_memory(%d, %lx, %ld) from %d\n", arg.arg_cpy.target, arg.arg_cpy.which, arg.arg_cpy.size, current->pid);
		if ((result = check_access(arg.arg_cpy.target)))
			return result;
		return copy_memory(arg.arg_cpy.target, arg.arg_cpy.which, arg.arg_cpy.size, (char __user *) arg.arg_cpy.buffer, COPY_FROM_USERSPACE);

	case IOCTL_READ_AUXV:
		if (copy_from_user(&arg.arg_cpy, (void *) argument, sizeof(struct ioctl_cpy)) != 0)
			return -EFAULT;
		TRACE("ioctl: read_auxv(%d, %ld) from %d\n", arg.arg_cpy.target, arg.arg_cpy.size, current->pid);
		if ((result = check_access(arg.arg_cpy.target)))
			return result;
		return read_auxv(arg.arg_cpy.target, arg.arg_cpy.size, (char __user *) arg.arg_cpy.buffer);

	case IOCTL_READ_REGISTERS:
		if (copy_from_user(&arg.arg_cpy, (void *) argument, sizeof(struct ioctl_cpy)) != 0)
			return -EFAULT;
		TRACE("ioctl: read_registers(%d, %lx) from %d\n", arg.arg_cpy.target, arg.arg_cpy.which, current->pid);
		if ((result = check_access(arg.arg_cpy.target)))
			return result;
		return copy_registers(arg.arg_cpy.target, arg.arg_cpy.which, (size_t __user *) PTR_AT(argument, struct ioctl_cpy, size), (char __user *) arg.arg_cpy.buffer, COPY_TO_USERSPACE);

	case IOCTL_WRITE_REGISTERS:
		if (copy_from_user(&arg.arg_cpy, (void *) argument, sizeof(struct ioctl_cpy)) != 0)
			return -EFAULT;
		TRACE("ioctl: write_registers(%d, %lx) from %d\n", arg.arg_cpy.target, arg.arg_cpy.which, current->pid);
		if ((result = check_access(arg.arg_cpy.target)))
			return result;
		return copy_registers(arg.arg_cpy.target, arg.arg_cpy.which, (size_t __user *) PTR_AT(argument, struct ioctl_cpy, size), (char __user *) arg.arg_cpy.buffer, COPY_FROM_USERSPACE);

	default:
		return -ENOTTY;
	}

	/* This should never be reached. If it is, we took some unsupported code path */
	return -EBADR;
}

/**
 * on_release - handles our control file being closed by a client
 * @inode: inode of the closed file
 * @fp:    closed file
 */
static int on_release(struct inode *inode, struct file *fp)
{
	/* Clean up all entries of the debugger here */
	struct debugger        *dbg;

	if (READ_ONCE(module_unloading))
		return 0;

	TRACE("on_release from TID %d, TGID %d\n", current->pid, current->tgid);

	mutex_lock(&data_mutex);

	dbg = __get_debugger(current->tgid);
	if (dbg == NULL)
		cleanup_and_return(0, mutex_unlock(&data_mutex));
	if (IS_ERR(dbg))
		cleanup_and_return(PTR_ERR(dbg), mutex_unlock(&data_mutex));
	__delete_debugger(dbg);

	mutex_unlock(&data_mutex);
	return 0;
}



/* Special events */


/**
 * handle_signal - Intercepts signal delivery (also in get_signal)
 *
 * Note that this differs from handle_get_signal in that we have access to the
 * actual signal information here. handle_get_signal intercepts the function
 * before the signal is even dequeued, which allows us to handle single-stepping
 * before ptrace gets a chance to do so. Here, ptrace is already done with the
 * signal, and the parent has been sent a SIGCHLD. We need to prevent this for
 * single-stepping SIGTRAPs, which is why we need two separate handlers.
 * In addition, this function will be called for each signal separately, which
 * is not guaranteed for handle_get_signal.
 *
 * @data:   Arbitrary data pointer, will be NULL.
 * @sig:    Signal number (e.g. SIGSEGV).
 * @info:   Signal metadata.
 * @action: The configured action.
 */
void handle_signal(void *data __attribute__((unused)), int sig, struct siginfo *info, struct k_sigaction *action)
{
	struct victim         *vct;
	struct debugger       *dbg;
	struct event_listener *lst;
	struct cancellation   *cancel;
	union event_data       evt_data;
	bool                   do_suspend;
	bool                   do_cancel;

	if (READ_ONCE(module_unloading))
		return;

	TRACE("handle_signal(%d) in PID %d", sig, current->pid);

	do_suspend = false;
	evt_data.signal = sig;

	/* Unlock the signal lock before obtaining the mutex */
	spin_unlock_irq(&current->sighand->siglock);
	mutex_lock(&data_mutex);

	/* Restore any sigactions we previously destroyed */
	__restore_sigactions();

	/* Find the victim task */
	vct = __get_victim(current->tgid);
	if (IS_ERR(vct) || vct == NULL)
		cleanup_and_return_void(mutex_unlock(&data_mutex), spin_lock_irq(&current->sighand->siglock));

	/* Check if anyone is listening for signals */
	list_for_each_entry(lst, &vct->event_listeners, node) {
		/* Wake up debuggers listening to the event */
		dbg = __get_debugger(lst->debugger_tgid);
		TRACE("Considering debugger %d (ptr = %p)\n", lst->debugger_tgid, (void*) dbg);
		if (IS_ERR(dbg) || dbg == NULL)
			continue;
		if (!(lst->event_mask & EVENT_SIGNAL))
			continue;

		do_suspend = true;
		__push_event(dbg, current->pid, EVENT_SIGNAL, evt_data);
		__lock_thread(lst->debugger_tgid, current->pid, SUSPEND_ON_SIGNAL);
		wake_up_thread(lst->debugger_tgid);
	}
	TRACE("All debuggers done, do_suspend = %d\n", do_suspend);

	/* Suspend if necessary */
	if (do_suspend)
		__suspend_loop();

	/* Check if we need to cancel the signal */
	do_cancel = false;
	hash_for_each_possible(signal_canceled, cancel, node, HASH_ID(current->pid)) {
		if (cancel->tid == current->pid) {
			cancel->state = CANCELLATION_HANDLED;
			do_cancel = true;
			break;
		}
	}

	/* Cancel the signal if it is not ignored already */
	if (do_cancel && action->sa.sa_handler != SIG_IGN) {
		/* Unfortunately, action->sa is the shared sigaction for the task.
		 * Modifying it has effects on all subsequent signals.
		 * We correct this above, or in handle_get_signal_return.
		 */

		cancel->state = CANCELLATION_MUST_RESTORE; /* Must restore this sigaction */
		cancel->action = action;                   /* Store a pointer to the action */
		cancel->handler = action->sa.sa_handler;   /* Store the original handler */
		action->sa.sa_handler = SIG_IGN;           /* Force the signal handler to SIG_IGN */
	}

	spin_lock_irq(&current->sighand->siglock);
	mutex_unlock(&data_mutex);
}

/**
 * handle_exit - Intercepts do_exit (task death)
 * @data: Arbitrary data pointer, will be NULL.
 * @task: Pointer to the exiting task.
 */
void handle_exit(void *data __attribute__((unused)), struct task_struct *task)
{
	struct debugger        *dbg;
	struct victim          *vct;
	struct breakpoint      *bp;
	struct breakpoint      *bp_it;
	struct attached_config *cfg;
	struct attached_config *cfg_it;
	struct thread_lock     *lck;
	struct thread_lock     *lck_it;
	struct single_step     *sst;
	struct single_step     *sst_it;
	struct event_listener  *lst;
	union event_data        evt_data;
	bool                    do_suspend;

	if (READ_ONCE(module_unloading))
		return;

	TRACE("handle_exit(task tid: %d, task tgid: %d, exit code: %d)\n", task->pid, task->tgid, task->exit_code);
	evt_data.exit_code = task->exit_code;
	do_suspend = false;

	mutex_lock(&data_mutex);
	__mark_exiting(task->pid, true);

	if (task->pid == task->tgid) {
		/* This is a thread group leader exiting. */

		/* If this is a debugger, remove everything. */
		dbg = __get_debugger(task->tgid);
		if (IS_ERR(dbg))
			cleanup_and_return_void(__mark_exiting(task->pid, false), mutex_unlock(&data_mutex));
		if (dbg != NULL)
			__delete_debugger(dbg);

		/* If this process has a victim thread, clean everything up too */
		vct = __get_victim(task->pid);
		if (IS_ERR(vct) || vct == NULL)
			cleanup_and_return_void(__mark_exiting(task->pid, false), mutex_unlock(&data_mutex));

		/* Now clean up the victim part: Force-detach all breakpoint configs, then delete all breakpoints and listeners, and finally delete the victim */
		list_for_each_entry_safe(bp, bp_it, &vct->breakpoints, node) {
			list_for_each_entry_safe(cfg, cfg_it, &bp->attached, breakpoint_node) {
				list_del(&cfg->debugger_node);
				list_del(&cfg->breakpoint_node);
				kfree(cfg);
			}
			__delete_breakpoint(bp);
		}
		list_for_each_entry_safe(lck, lck_it, &vct->locks, victim_node) {
			list_del(&lck->victim_node);
			list_del(&lck->debugger_node);
			kfree(lck);
		}
		list_for_each_entry_safe(sst, sst_it, &vct->step_listeners, node) {
			list_del(&sst->node);
			kfree(sst);
		}
		list_for_each_entry(lst, &vct->event_listeners, node) {
			/* Wake up debuggers listening to the exit event */
			dbg = __get_debugger(lst->debugger_tgid);
			if (IS_ERR(dbg) || dbg == NULL)
				continue;
			if (!(lst->event_mask & EVENT_EXIT))
				continue;

			do_suspend = true;
			__push_event(dbg, task->pid, EVENT_EXIT, evt_data);
			__lock_thread(lst->debugger_tgid, task->pid, SUSPEND_ON_EXIT);
			wake_up_thread(lst->debugger_tgid);
		}

		/* TODO: This doesn't work... I assume the task state is so bad already that we just get killed at schedule() */
		if (do_suspend)
			__suspend_loop();

		__delete_victim(vct);
	} else {
		/* This is just a thread, not the entire process. Keep debuggers alive, just clean up relevant victim stuff */
		vct = __get_victim(task->pid);
		if (IS_ERR(vct) || vct == NULL)
			cleanup_and_return_void(__mark_exiting(task->pid, false), mutex_unlock(&data_mutex));

		/* Now clean up the victim part: Delete all thread locks and step listeners for this thread. */
		list_for_each_entry_safe(lck, lck_it, &vct->locks, victim_node) {
			if (lck->victim_tid != task->pid)
				continue;
			list_del(&lck->victim_node);
			list_del(&lck->debugger_node);
			kfree(lck);
		}
		list_for_each_entry_safe(sst, sst_it, &vct->step_listeners, node) {
			if (sst->victim_tid != task->pid)
				continue;
			list_del(&sst->node);
			kfree(sst);
		}
		list_for_each_entry(lst, &vct->event_listeners, node) {
			/* Wake up debuggers listening to the exit event */
			dbg = __debugger(lst->debugger_tgid);
			if (IS_ERR(dbg))
				continue;
			if (!(lst->event_mask & EVENT_EXIT))
				continue;

			do_suspend = true;
			__push_event(dbg, task->pid, EVENT_EXIT, evt_data);
			__lock_thread(lst->debugger_tgid, task->pid, SUSPEND_ON_EXIT);
			wake_up_thread(lst->debugger_tgid);
		}

		if (do_suspend)
			__suspend_loop();
	}

	__mark_exiting(task->pid, false);
	mutex_unlock(&data_mutex);
}

/**
 * handle_clone - Intercepts copy_process (fork/vfork/clone)
 * @data:  Arbitrary data pointer, will be NULL.
 * @child: The newly created task
 * @flags: The flags provided to copy_process.
 *
 * Flags are directly forwarded from clone().
 * For fork(), flags = SIGCHLD.
 * For vfork(), flags = CLONE_VFORK | CLONE_VM | SIGCHLD.
 * The parent task (calling clone() or similar functions) is the current task.
 */
void handle_clone(void *data __attribute__((unused)), struct task_struct *child, unsigned long flags)
{
	struct debugger       *dbg;
	struct victim         *vct;
	struct event_listener *lst;
	union event_data       evt_data;
	bool                   do_suspend;

	if (READ_ONCE(module_unloading))
		return;

	TRACE("handle_clone(parent tid: %d, new tid: %d, flags: %ld)\n", current->pid, child->pid, flags);

	evt_data.clone_data.new_task_tid = child->pid;
	evt_data.clone_data.clone_flags = flags;
	do_suspend = false;

	mutex_lock(&data_mutex);

	/* Get the victim entry (if any) */
	vct = __get_victim(current->pid);
	if (IS_ERR(vct) || vct == NULL)
		cleanup_and_return_void(mutex_unlock(&data_mutex));

	/* Find all attached event listeners */
	list_for_each_entry(lst, &vct->event_listeners, node) {
		/* Wake up debuggers listening to the clone event */
		dbg = __get_debugger(lst->debugger_tgid);
		if (IS_ERR(dbg) || dbg == NULL)
			continue;
		if (!(lst->event_mask & EVENT_CLONE))
			continue;

		do_suspend = true;
		__push_event(dbg, current->pid, EVENT_CLONE, evt_data);
		__lock_thread(lst->debugger_tgid, current->pid, SUSPEND_ON_CLONE);
		wake_up_thread(lst->debugger_tgid);
	}

	if (do_suspend)
		__suspend_loop();

	mutex_unlock(&data_mutex);
}

/**
 * handle_exec - Intercepts exec_binprm (execve/...)
 * @data: Arbitrary data pointer, will be NULL.
 * @task: The task performing the exec.
 * @tid:  The TID of the thread calling exec (it will be reset to the thread's TGID, and all other threads will exit)
 * @bprm: The binary that will be executed.
 */
void handle_exec(void *data __attribute__((unused)), struct task_struct *task, pid_t tid, struct linux_binprm *bprm)
{
	struct debugger       *dbg;
	struct victim         *vct;
	struct event_listener *lst;
	union event_data       evt_data;
	bool                   do_suspend;

	if (READ_ONCE(module_unloading))
		return;

	TRACE("handle_exec(%d / %d, new fn: %s, new interp: %s)\n", task->tgid, tid, bprm->filename, bprm->interp);

	evt_data.exec_data.calling_tid = tid;
	strncpy(evt_data.exec_data.filename, bprm->filename, sizeof(evt_data.exec_data.filename) - 1);
	do_suspend = false;

	mutex_lock(&data_mutex);

	/* Get the victim entry (if any) */
	vct = __get_victim(current->pid);
	if (IS_ERR(vct) || vct == NULL)
		cleanup_and_return_void(mutex_unlock(&data_mutex));

	/* Find all attached event listeners */
	list_for_each_entry(lst, &vct->event_listeners, node) {
		/* Wake up debuggers listening to the clone event */
		dbg = __get_debugger(lst->debugger_tgid);
		if (IS_ERR(dbg) || dbg == NULL)
			continue;
		if (!(lst->event_mask & EVENT_EXEC))
			continue;

		do_suspend = true;
		__push_event(dbg, current->pid, EVENT_EXEC, evt_data);
		__lock_thread(lst->debugger_tgid, current->pid, SUSPEND_ON_EXEC);
		wake_up_thread(lst->debugger_tgid);
	}

	if (do_suspend)
		__suspend_loop();

	/* TODO: Clean up old breakpoints here */

	mutex_unlock(&data_mutex);
}


/* File setup */

static struct file_operations file_ops = {
	.owner          = THIS_MODULE,
	.release        = on_release,    /* Call on_release when the file is closed */
	.unlocked_ioctl = on_ioctl,      /* Call on_ioctl on any incoming IOCTL */
};
static dev_t         first_device;
static struct class *device_class;
static struct cdev   device;
#define DEVICE_NAME       "debugging"
#define DEVICE_CLASS_NAME "debugging"
#define DEVICE_FILE_NAME  "debugging"
#define DEVICE_FIRST_MINOR 0
#define DEVICE_MINOR_COUNT 1

static char *device_node(struct device *dev, umode_t *mode)
{
	if (mode != NULL)
		*mode = 0666;
	return NULL;
}



/* Module initialization and cleanup */

static int initialization_error = 0;

/**
 * maybe_register_tracepoint - Register a tracepoint handler if the tracepoint matches pre-defined values
 * @tp:   The tracepoint in question.
 * @data: A value passed from for_each_kernel_tracepoint, should be NULL.
 */
static void maybe_register_tracepoint(struct tracepoint *tp, void *data)
{
	if (initialization_error) return;
	else if (strcmp(tp->name, "sched_process_exit") == 0) initialization_error = tracepoint_probe_register(tp, (void *) handle_exit, NULL);
	else if (strcmp(tp->name, "task_newtask") == 0)       initialization_error = tracepoint_probe_register(tp, (void *) handle_clone, NULL);
	else if (strcmp(tp->name, "sched_process_exec") == 0) initialization_error = tracepoint_probe_register(tp, (void *) handle_exec, NULL);
	else if (strcmp(tp->name, "signal_deliver") == 0)     initialization_error = tracepoint_probe_register(tp, (void *) handle_signal, NULL);
}

/**
 * maybe_unregister_tracepoint - Unregisters tracepoint handlers that were registered in maybe_register_tracepoint
 * @tp:   The tracepoint in question.
 * @data: A value passed from for_each_kernel_tracepoint, should be NULL.
 */
static void maybe_unregister_tracepoint(struct tracepoint *tp, void *data)
{
	if      (strcmp(tp->name, "sched_process_exit") == 0) tracepoint_probe_unregister(tp, (void *) handle_exit, NULL);
	else if (strcmp(tp->name, "task_newtask") == 0)       tracepoint_probe_unregister(tp, (void *) handle_clone, NULL);
	else if (strcmp(tp->name, "sched_process_exec") == 0) tracepoint_probe_unregister(tp, (void *) handle_exec, NULL);
	else if (strcmp(tp->name, "signal_deliver") == 0)     tracepoint_probe_unregister(tp, (void *) handle_signal, NULL);
}

static int __init initialize(void)
{
	/* Create character device */
	if (alloc_chrdev_region(&first_device, DEVICE_FIRST_MINOR, DEVICE_MINOR_COUNT, DEVICE_NAME) != 0)
		return -ENODEV;
	if ((device_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME)) == NULL) {
		unregister_chrdev_region(first_device, DEVICE_MINOR_COUNT);
		return -ENODEV;
	}
	device_class->devnode = device_node; /* This will set the device to mode 0666 (-rw-rw-rw-) */
	if (device_create(device_class, NULL, first_device, NULL, DEVICE_FILE_NAME) == NULL) {
		class_destroy(device_class);
		unregister_chrdev_region(first_device, DEVICE_MINOR_COUNT);
		return -ENODEV;
	}
	cdev_init(&device, &file_ops);
	if (cdev_add(&device, first_device, DEVICE_MINOR_COUNT) < 0) {
		device_destroy(device_class, first_device);
		class_destroy(device_class);
		unregister_chrdev_region(first_device, DEVICE_MINOR_COUNT);
		return -ENODEV;
	}

	/* Create cleanup queue */
	deferred_queue = create_workqueue("cleanup");
	if (deferred_queue == NULL)
		return -ENOMEM;

	/* Look up symbols */
	ks_wait_task_inactive = (unsigned long (*)(struct task_struct *, long)) kallsyms_lookup_name("wait_task_inactive");
	ks_user_enable_single_step = (void (*)(struct task_struct *)) kallsyms_lookup_name("user_enable_single_step");
	ks_user_disable_single_step = (void (*)(struct task_struct *)) kallsyms_lookup_name("user_disable_single_step");
	ks_get_signal = (int (*)(struct ksignal *)) kallsyms_lookup_name("get_signal");
	ks_dequeue_signal = (int (*)(struct task_struct *, sigset_t *, siginfo_t *)) kallsyms_lookup_name("dequeue_signal");
	ks_security_ptrace_access_check = (int (*)(struct task_struct *, unsigned int)) kallsyms_lookup_name("security_ptrace_access_check");

	if (ks_wait_task_inactive == NULL || ks_user_enable_single_step == NULL || ks_user_disable_single_step == NULL || ks_get_signal == NULL || ks_dequeue_signal == NULL)
		return -ENOENT;

	if (ks_security_ptrace_access_check == NULL)
		printk(KERN_WARNING "Cannot delegate access checks to security modules\n");

	/* Register signal intercept */
	signal_probe.kp.addr = (kprobe_opcode_t *) ks_get_signal;
	signal_probe.entry_handler = &handle_get_signal;
	signal_probe.handler = &handle_get_signal_return;
	initialization_error = register_kretprobe(&signal_probe);
	if (initialization_error)
		return initialization_error;

	/* Register tracepoint handlers */
	for_each_kernel_tracepoint(maybe_register_tracepoint, NULL);
	if (initialization_error)
		return initialization_error;

	return 0;
}

static void __exit cleanup(void)
{
	int                     bucket;
	struct hlist_node      *hlist_it;
	struct debugger        *dbg;
	struct victim          *vct;
	struct breakpoint      *bp;
	struct breakpoint      *bp_it;
	struct attached_config *cfg;
	struct attached_config *cfg_it;
	struct thread_lock     *lck;
	struct thread_lock     *lck_it;
	struct single_step     *sst;
	struct single_step     *sst_it;

	/* First, remove the debugging device to make sure that no new requests come in */
	cdev_del(&device);
	device_destroy(device_class, first_device);
	class_destroy(device_class);
	unregister_chrdev_region(first_device, DEVICE_MINOR_COUNT);

	/* Indicate to all threads that the module is unloading */
	module_unloading = true;
	smp_mb();

	/* Acquire the mutex */
	mutex_lock(&data_mutex);

	/* Detach all debuggers */
	hash_for_each_safe(debuggers, bucket, hlist_it, dbg, node)
		__delete_debugger(dbg);

	/* Remove all victims */
	hash_for_each_safe(victims, bucket, hlist_it, vct, node) {
		/* Force-detach all breakpoint configs, then delete all breakpoints and listeners, and finally delete the victim */
		list_for_each_entry_safe(bp, bp_it, &vct->breakpoints, node) {
			list_for_each_entry_safe(cfg, cfg_it, &bp->attached, breakpoint_node) {
				list_del(&cfg->debugger_node);
				list_del(&cfg->breakpoint_node);
				kfree(cfg);
			}
			__delete_breakpoint(bp);
		}
		list_for_each_entry_safe(lck, lck_it, &vct->locks, victim_node) {
			list_del(&lck->victim_node);
			list_del(&lck->debugger_node);
			kfree(lck);
		}
		list_for_each_entry_safe(sst, sst_it, &vct->step_listeners, node) {
			list_del(&sst->node);
			kfree(sst);
		}
		__delete_victim(vct);
	}

	/* Remove general probes */
	unregister_kretprobe(&signal_probe);
	for_each_kernel_tracepoint(maybe_unregister_tracepoint, NULL);

	mutex_unlock(&data_mutex);

	/* TODO: We should wait until all uprobes have been deleted */
	flush_workqueue(deferred_queue);
	destroy_workqueue(deferred_queue);
}

module_init(initialize)
module_exit(cleanup)
