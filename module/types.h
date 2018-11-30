#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/uprobes.h>
#include <linux/workqueue.h>

/*
 * The following code uses TGID to describe the ID of a user-space process
 * (TGID in kernel-space, PID in user-space), and TID to describe the ID of
 * a user-space thread (PID in kernel-space, TID in user-space)
 */

/**
 * addr_t - Any address in memory
 */
typedef unsigned long addr_t;

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
 * @node:           Entry in the victim hash table (by TGID)
 * @tgid:           TGID of the victim
 * @breakpoints:    Breakpoints in the victim process
 * @locks:          Locks for the victim thread
 * @step_listeners: Attached single-step listeners (each is only valid for a specific TID)
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
 * exit_marker - Marks a victim thread as exiting, blocking certain operations from running
 * @node: Entry in the hash table (by TID)
 * @tid:  TID of the victim thread
 */
struct exit_marker {
	struct hlist_node node;
	pid_t             tid;
};

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

	union event_data {
		int suspension_reason; /* EVENT_SUSPEND */
		int exit_code;         /* EVENT_EXIT */
		int signal;            /* EVENT_SIGNAL */

		/* EVENT_CLONE */
		struct {
			pid_t         new_task_tid;
			unsigned long clone_flags;
		} clone_data;

		/* EVENT_EXEC */
		struct {
			pid_t calling_tid;
			char  filename[NAME_MAX + 1];
		} exec_data;
	} data;
};

/** Suspension reasons */
#define NOT_SUSPENDED          0
#define SUSPEND_EXPLICIT       1
#define SUSPEND_ON_BREAK       2
#define SUSPEND_ON_SINGLE_STEP 3
#define SUSPEND_ON_EXIT        4
#define SUSPEND_ON_CLONE       5
#define SUSPEND_ON_EXEC        6
#define SUSPEND_ON_SIGNAL      7

/** Event types */
#define EVENT_SUSPEND     (1 << 0)
#define EVENT_EXIT        (1 << 1)
#define EVENT_CLONE       (1 << 2)
#define EVENT_EXEC        (1 << 3)
#define EVENT_SIGNAL      (1 << 4)



/* Communication-only types */

/**
 * ioctl_tid_or_tgid
 * @id:   TID or TGID
 * @type: Indicates the type of the ID
 */
struct ioctl_tid_or_tgid {
	pid_t              id;
	enum { TID, TGID } type;
};

/**
 * ioctl_enumeration
 * @target:    Target process. Whether this has any meaning depends on the IOCTL used.
 * @buffer:    Buffer of items.
 * @size:      Size of the buffer (in number of items). In the response, indicates how many items were written to the buffer.
 * @available: Number of suspended threads currently available.
 *
 * If the response size is smaller than the available size, query again with a larger buffer.
 * The type (and size) of an item is defined by the call this type is used for.
 */
struct ioctl_enumeration {
	pid_t  target;
	addr_t buffer;
	size_t size;
	size_t available;
};

/**
 * ioctl_breakpoint_identifier
 * @target:  TGID of the target process
 * @address: Address of the breakpoint
 */
struct ioctl_breakpoint_identifier {
	pid_t  target;
	addr_t address;
};

/**
 * ioctl_cpy
 * @target:  TID or TGID of the target
 * @which:   Address at which to begin copying (for memory) or type of the register set (for registers, usually NT_PRSTATUS = 1)
 * @buffer:  Pointer to userspace buffer
 * @size:    Size of the buffer that will be copied (register requests set this to the size of the full set)
 */
struct ioctl_cpy {
	pid_t  target;
	addr_t which;
	addr_t buffer;
	size_t size;
};

/**
 * ioctl_flag
 * @target: TID or TGID of the target
 * @value:  Value of the flag
 */
struct ioctl_flag {
	pid_t target;
	int   value;
};

/**
 * ioctl_argument
 * Holds any of the ioctl argument types
 */
union ioctl_argument {
	struct ioctl_tid_or_tgid           arg_id;
	struct ioctl_enumeration           arg_enumeration;
	struct ioctl_breakpoint_identifier arg_breakpoint;
	struct ioctl_cpy                   arg_cpy;
	struct ioctl_flag                  arg_flag;
};


/* Helper types */

/** dead_breakpoint - Holds a cleanup task for a dead breakpoint */
struct dead_breakpoint {
	struct work_struct  work;
	struct breakpoint  *bp;
};

/** ioctl_event - Holds an event for the IOCTL buffer */
struct ioctl_event {
	int              event_id;
	pid_t            victim_tid;
	union event_data data;
};
