#ifndef PLUTONIUM_DBG_COMMON_H
#define PLUTONIUM_DBG_COMMON_H

/*
 * This file is intended for use by both user-space and kernel-space code.
 * Language bindings should feel free to include this file to obtain necessary
 * struct layouts and constant values and to extract the IOCTL command IDs.
 * Please make sure that changes do not break anything in either mode!
 * Note that throughout plutonium-dbg, we use "TGID" to describe the ID of a
 * full user-space process (this value is called TGID in kernel-space, but is
 * generally called PID in user-space), and "TID" to describe the ID of a
 * user-space thread (this is what the kernel refers to as a PID, but user-space
 * calls this the TID, see e.g. man 2 gettid).
 * Data structures and constants only used in module code (especially those that
 * pull in kernel headers for anything except trivial types like pid_t) should
 * go in the types.h header, not here.
 */

#ifdef __KERNEL__
	#include <linux/fs.h>
	#include <linux/types.h>
#else
	#include <sys/ioctl.h>
	#include <sys/param.h>
	#include <sys/types.h>
#endif


/* Basic types */

/**
 * addr_t - Any address in memory
 */
typedef unsigned long addr_t;

/**
 * event_data - Additional data for a debugger event
 * @suspension_reason: On EVENT_SUSPEND, contains one of the SUSPEND_ constants
 *                     indicating the reason why a thread was suspended.
 * @exit_code:         On EVENT_EXIT, this member holds the exit code.
 * @signal:            The signal number for EVENT_SIGNAL.
 * @clone_data:        Flags to clone() and the created TID for EVENT_CLONE.
 * @exec_data:         Previous TID and the new filename for EVENT_EXEC.
 */
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
};


/* Constants */

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


/* Communication-only types (i.e. arguments to IOCTL) */

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

/**
 * ioctl_event
 * Holds an event for the IOCTL buffer
 */
struct ioctl_event {
	int              event_id;
	pid_t            victim_tid;
	union event_data data;
};


/* IOCTL codes */

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

#endif /* PLUTONIUM_DBG_COMMON_H */
