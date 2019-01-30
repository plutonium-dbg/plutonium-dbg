#ifndef PLUTONIUM_DBG_TYPES_H
#define PLUTONIUM_DBG_TYPES_H

#ifndef __KERNEL__
#error "You should only include 'types.h' from kernel code"
#endif

#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/uprobes.h>
#include <linux/workqueue.h>

#include "common.h" /* Pull in shared types and constants */


/* Internal types */

/**
 * probe_location - Location of a probe underlying a breakpoint
 * @inode:  The inode in which the probe is contained
 * @offset: Offset of the probe in the inode
 */
struct probe_location {
	struct inode *inode;
	loff_t        offset;
};

/**
 * breakpoint - A breakpoint
 * @node:     Entry in the victim's breakpoint list
 * @target:   The TGID of the victim this breakpoint is valid for
 * @address:  The address of the breakpoint, in the victim's address space
 * @inode:    The inode in which the underlying probe is contained
 * @offset:   Offset of the underlying probe in the inode
 * @attached: A list of attached configurations.
 * @counter:  Number of locks currently held at this breakpoint
 * @state:    Breakpoint state
 */
struct breakpoint {
	struct list_head        node;
	pid_t                   target;
	addr_t                  address;
	struct probe_location   probe;
	struct list_head        attached;
	struct uprobe_consumer  handler;

	atomic_t                counter;
	int                     state;
};
#define BP_STATE_ACTIVE 0
#define BP_STATE_DEAD   1

/**
 * attached_config - Configuration of a breakpoint for a specific client
 * @breakpoint_node: Entry in the breakpoint configuration list
 * @debugger_node:   Entry in the debugger's config list
 * @breakpoint_ref:  The breakpoint this entry is for
 * @debugger_tgid:   TGID of the debugging process
 */
struct attached_config {
	struct list_head   breakpoint_node;
	struct list_head   debugger_node;
	struct breakpoint *breakpoint_ref;
	pid_t              debugger_tgid;
};

/**
 * debugger - A debugging process
 * @node:        Entry in the debugger hash table (by TGID)
 * @tgid:        TGID of the debugger
 * @breakpoints: Breakpoint configurations held by this debugger
 * @locks:       Thread locks held by this debugger
 * @event_queue: Events pending for this debugger
 */
struct debugger {
	struct hlist_node node;
	pid_t             tgid;
	struct list_head  breakpoints;
	struct list_head  locks;
	struct list_head  event_queue;
};

/**
 * victim - A victim process
 * @node:            Entry in the victim hash table (by TGID)
 * @tgid:            TGID of the victim
 * @breakpoints:     Breakpoints in the victim process
 * @locks:           Locks for the victim thread
 * @step_listeners:  Attached single-step listeners (each is only valid for a specific TID)
 * @event_listeners: Attached event listeners
 */
struct victim {
	struct hlist_node node;
	pid_t             tgid;
	struct list_head  breakpoints;
	struct list_head  locks;
	struct list_head  step_listeners;
	struct list_head  event_listeners;
};

/**
 * thread_marker - Marks a victim thread in a hash table.
 * @node: Entry in the hash table (by TID)
 * @tid:  TID of the victim thread
 */
struct thread_marker {
	struct hlist_node node;
	pid_t             tid;
};

/**
 * cancellation - Data needed to cancel a signal, but restore the sigaction (see handle_signal)
 * @node:    Entry in a hash table
 * @tid:     TID of the victim thread
 * @restore: Whether we need to restore the sigaction in the first place
 * @action:  The modified sigaction
 * @handler: The original signal handler
 */
struct cancellation {
	struct hlist_node   node;
	pid_t               tid;
	int                 state;
	struct k_sigaction *action;
	__sighandler_t      handler;
};
#define CANCELLATION_PENDING      0
#define CANCELLATION_HANDLED      1
#define CANCELLATION_MUST_RESTORE 2

/**
 * thread_lock - Locks a suspended thread until it can continue
 * @victim_node:     Entry in the victim's list of locks
 * @debugger_node:   Entry in the debugger's list of held locks
 * @victim_tid:      TID of the suspended thread
 * @debugger_tgid:   TGID of the blocking debugger
 * @reason:          Suspension reason
 * @event_submitted: Whether the EVENT_SUSPEND was already sent to the event queue
 */
struct thread_lock {
	struct list_head victim_node;
	struct list_head debugger_node;
	pid_t            victim_tid;
	pid_t            debugger_tgid;
	int              reason;
	bool             event_submitted;
};

/**
 * single_step - Single-step listener for a victim thread
 * @node:          Entry in the victim's list of single-step listeners
 * @victim_tid:    TID of the victim thread
 * @debugger_tgid: TGID of the debugger
 */
struct single_step {
	struct list_head node;
	pid_t            victim_tid;
	pid_t            debugger_tgid;
};

/**
 * event_listener - Event listeners for a victim process
 * @node:          Entry in the list of event listeners
 * @debugger_tgid: TGID of the listening debugger
 * @event_mask:    Mask of which events to pass to the debugger
 * @suspend_mask:  Mask specifying on which events the target should be suspended
 *
 * EVENT_SUSPEND is special - it does not require a registered event listener,
 * and suspend_mask has no effect on it (for obvious reasons).
 */
struct event_listener {
	struct list_head node;
	pid_t            debugger_tgid;
	int              event_mask;
	int              suspend_mask;
};

/**
 * event - An event
 * @node:       Entry in the event queue
 * @event_id:   The event
 * @victim_tid: TID of the victim thread
 * @data:       Additional event data
 */
struct event {
	struct list_head node;
	int              event_id;
	pid_t            victim_tid;
	union event_data data;
};


/* Helper types */

/** dead_breakpoint - Holds a cleanup task for a dead breakpoint */
struct dead_breakpoint {
	struct work_struct  work;
	struct breakpoint  *bp;
};

#endif /* PLUTONIUM_DBG_TYPES_H */
