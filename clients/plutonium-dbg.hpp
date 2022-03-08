#ifndef PLUTONIUM_DBG_NS
	#define PLUTONIUM_DBG_NS plutonium_dbg
#endif

#ifndef PLUTONIUM_DBG_PATH
	#define PLUTONIUM_DBG_PATH "/dev/debugging"
#endif

extern "C"
{
    #include "../module/common.h"
    typedef struct ioctl_event ioctl_event;
}

namespace PLUTONIUM_DBG_NS
{
	int continue_thread(pid_t tid);
	int continue_process(pid_t tgid);
	int suspend_thread(pid_t tid);
	int suspend_process(pid_t tgid);
	int install_breakpoint(pid_t tgid, addr_t address);
	int remove_breakpoint(pid_t tgid, addr_t address);
	int thread_set_stepping(pid_t tid, bool step);
	int set_event_mask(pid_t tgid, int mask);
	ssize_t wait(ioctl_event *event_buffer, size_t buffer_size);
	ssize_t wait_for(pid_t tid, ioctl_event *event_buffer, size_t buffer_size);
	ssize_t events(ioctl_event *event_buffer, size_t buffer_size);
	ssize_t status(pid_t *tid_buffer, size_t buffer_size);
	ssize_t enumerate_threads(pid_t tgid, pid_t *tid_buffer, size_t buffer_size);
	int suspension_reason(pid_t tid);
	int read_memory(pid_t tgid, addr_t address, unsigned char *buffer, size_t size);
	int write_memory(pid_t tgid, addr_t address, const unsigned char *buffer, size_t size);
	ssize_t read_registers(pid_t tid, int request_type, unsigned char *buffer, size_t size);
	int write_registers(pid_t tid, int request_type, const unsigned char *buffer, size_t size);
	int read_auxv(pid_t tid, unsigned char *buffer, size_t size);
	int cancel_signal(pid_t tid);
}
