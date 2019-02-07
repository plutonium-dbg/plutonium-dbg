#include "plutonium-dbg.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int PLUTONIUM_DBG_NAME(open_debugger)(void)
{
	return open("/dev/debugging", O_RDONLY | O_CLOEXEC);
}

void PLUTONIUM_DBG_NAME(close_debugger)(int fd)
{
	close(fd);
}

int PLUTONIUM_DBG_NAME(continue_thread)(int fd, pid_t tid)
{
	struct ioctl_tid_or_tgid argument = { tid, TID };
	return ioctl(fd, IOCTL_CONTINUE, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(continue_process)(int fd, pid_t tgid)
{
	struct ioctl_tid_or_tgid argument = { tgid, TGID };
	return ioctl(fd, IOCTL_CONTINUE, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(suspend_thread)(int fd, pid_t tid)
{
	struct ioctl_tid_or_tgid argument = { tid, TID };
	return ioctl(fd, IOCTL_SUSPEND, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(suspend_process)(int fd, pid_t tgid)
{
	struct ioctl_tid_or_tgid argument = { tgid, TGID };
	return ioctl(fd, IOCTL_SUSPEND, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(install_breakpoint)(int fd, pid_t tgid, addr_t address)
{
	struct ioctl_breakpoint_identifier argument = { tgid, address };
	return ioctl(fd, IOCTL_INSTALL_BREAKPOINT, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(remove_breakpoint)(int fd, pid_t tgid, addr_t address)
{
	struct ioctl_breakpoint_identifier argument = { tgid, address };
	return ioctl(fd, IOCTL_REMOVE_BREAKPOINT, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(thread_set_stepping)(int fd, pid_t tid, bool step)
{
	struct ioctl_flag argument = { tid, step };
	return ioctl(fd, IOCTL_SET_STEP, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(set_event_mask)(int fd, pid_t tgid, int mask)
{
	struct ioctl_flag argument = { tgid, mask };
	return ioctl(fd, IOCTL_SET_EVENT_MASK, (char *) &argument);
}

ssize_t PLUTONIUM_DBG_NAME(wait)(int fd, struct ioctl_event *event_buffer, size_t buffer_size)
{
	struct ioctl_enumeration argument = { 0, (addr_t) event_buffer, buffer_size, 0 };
	int error = ioctl(fd, IOCTL_WAIT, (char *) &argument);
	if (error < 0)
		return error;
	return argument.size;
}

ssize_t PLUTONIUM_DBG_NAME(wait_for)(int fd, pid_t tid, struct ioctl_event *event_buffer, size_t buffer_size)
{
	struct ioctl_enumeration argument = { tid, (addr_t) event_buffer, buffer_size, 0 };
	int error = ioctl(fd, IOCTL_WAIT_FOR, (char *) &argument);
	if (error < 0)
		return error;
	return argument.size;
}

ssize_t PLUTONIUM_DBG_NAME(events)(int fd, struct ioctl_event *event_buffer, size_t buffer_size)
{
	struct ioctl_enumeration argument = { 0, (addr_t) event_buffer, buffer_size, 0 };
	int error = ioctl(fd, IOCTL_EVENTS, (char *) &argument);
	if (error < 0)
		return error;
	return argument.size;
}

ssize_t PLUTONIUM_DBG_NAME(status)(int fd, pid_t *tid_buffer, size_t buffer_size)
{
	struct ioctl_enumeration argument = { 0, (addr_t) tid_buffer, buffer_size, 0 };
	int error = ioctl(fd, IOCTL_STATUS, (char *) &argument);
	if (error < 0)
		return error;
	return argument.size;
}

ssize_t PLUTONIUM_DBG_NAME(enumerate_threads)(int fd, pid_t tgid, pid_t *tid_buffer, size_t buffer_size)
{
	struct ioctl_enumeration argument = { tgid, (addr_t) tid_buffer, buffer_size, 0 };
	int error = ioctl(fd, IOCTL_ENUMERATE_THREADS, (char *) &argument);
	if (error < 0)
		return error;
	return argument.size;
}

int PLUTONIUM_DBG_NAME(suspension_reason)(int fd, pid_t tid)
{
	struct ioctl_flag argument = { tid, 0 };
	int error = ioctl(fd, IOCTL_SUSPEND_REASON, (char *) &argument);
	if (error < 0)
		return error;
	return argument.value;
}

int PLUTONIUM_DBG_NAME(read_memory)(int fd, pid_t tgid, addr_t address, unsigned char *buffer, size_t size)
{
	struct ioctl_cpy argument = { tgid, address, (addr_t) buffer, size };
	return ioctl(fd, IOCTL_READ_MEMORY, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(write_memory)(int fd, pid_t tgid, addr_t address, const unsigned char *buffer, size_t size)
{
	struct ioctl_cpy argument = { tgid, address, (addr_t) buffer, size };
	return ioctl(fd, IOCTL_WRITE_MEMORY, (char *) &argument);
}

ssize_t PLUTONIUM_DBG_NAME(read_registers)(int fd, pid_t tid, int request_type, unsigned char *buffer, size_t size)
{
	struct ioctl_cpy argument = { tid, request_type, (addr_t) buffer, size };
	int error = ioctl(fd, IOCTL_READ_REGISTERS, (char *) &argument);
	if (error < 0)
		return error;
	return argument.size;
}

int PLUTONIUM_DBG_NAME(write_registers)(int fd, pid_t tid, int request_type, const unsigned char *buffer, size_t size)
{
	struct ioctl_cpy argument = { tid, request_type, (addr_t) buffer, size };
	return ioctl(fd, IOCTL_READ_REGISTERS, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(read_auxv)(int fd, pid_t tid, unsigned char *buffer, size_t size)
{
	struct ioctl_cpy argument = { tid, 0, (addr_t) buffer, size };
	return ioctl(fd, IOCTL_READ_AUXV, (char *) &argument);
}

int PLUTONIUM_DBG_NAME(cancel_signal)(int fd, pid_t tid)
{
	struct ioctl_tid_or_tgid argument = { tid, TID };
	return ioctl(fd, IOCTL_CANCEL_SIGNAL, (char *) &argument);
}
