#include <stdbool.h>
#include "../module/common.h"

/* Allow users to specify custom function prefixes */

#ifndef PLUTONIUM_DBG_PREFIX
	#define PLUTONIUM_DBG_PREFIX plutonium_
#endif

#define PLUTONIUM_DBG_TOKEN_PASTE_IMPL(prefix, token) prefix##token
#define PLUTONIUM_DBG_TOKEN_PASTE(prefix, token) PLUTONIUM_DBG_TOKEN_PASTE_IMPL(prefix, token)
#define PLUTONIUM_DBG_NAME(token) PLUTONIUM_DBG_TOKEN_PASTE(PLUTONIUM_DBG_PREFIX, token)


/* Interface */

int PLUTONIUM_DBG_NAME(open_debugger)(void);
void PLUTONIUM_DBG_NAME(close_debugger)(int fd);

int PLUTONIUM_DBG_NAME(continue_thread)(int fd, pid_t tid);
int PLUTONIUM_DBG_NAME(continue_process)(int fd, pid_t tgid);
int PLUTONIUM_DBG_NAME(suspend_thread)(int fd, pid_t tid);
int PLUTONIUM_DBG_NAME(suspend_process)(int fd, pid_t tgid);
int PLUTONIUM_DBG_NAME(install_breakpoint)(int fd, pid_t tgid, addr_t address);
int PLUTONIUM_DBG_NAME(remove_breakpoint)(int fd, pid_t tgid, addr_t address);
int PLUTONIUM_DBG_NAME(thread_set_stepping)(int fd, pid_t tid, bool step);
int PLUTONIUM_DBG_NAME(set_event_mask)(int fd, pid_t tgid, int mask);
ssize_t PLUTONIUM_DBG_NAME(wait)(int fd, struct ioctl_event *event_buffer, size_t buffer_size);
ssize_t PLUTONIUM_DBG_NAME(wait_for)(int fd, pid_t tid, struct ioctl_event *event_buffer, size_t buffer_size);
ssize_t PLUTONIUM_DBG_NAME(events)(int fd, struct ioctl_event *event_buffer, size_t buffer_size);
ssize_t PLUTONIUM_DBG_NAME(status)(int fd, pid_t *tid_buffer, size_t buffer_size);
ssize_t PLUTONIUM_DBG_NAME(enumerate_threads)(int fd, pid_t tgid, pid_t *tid_buffer, size_t buffer_size);
int PLUTONIUM_DBG_NAME(suspension_reason)(int fd, pid_t tid);
int PLUTONIUM_DBG_NAME(read_memory)(int fd, pid_t tgid, addr_t address, unsigned char *buffer, size_t size);
int PLUTONIUM_DBG_NAME(write_memory)(int fd, pid_t tgid, addr_t address, const unsigned char *buffer, size_t size);
ssize_t PLUTONIUM_DBG_NAME(read_registers)(int fd, pid_t tid, int request_type, unsigned char *buffer, size_t size);
int PLUTONIUM_DBG_NAME(write_registers)(int fd, pid_t tid, int request_type, const unsigned char *buffer, size_t size);
int PLUTONIUM_DBG_NAME(read_auxv)(int fd, pid_t tid, unsigned char *buffer, size_t size);
int PLUTONIUM_DBG_NAME(cancel_signal)(int fd, pid_t tid);

