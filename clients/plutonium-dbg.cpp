#include "plutonium-dbg.hpp"

extern "C"
{
    #include <fcntl.h>
    #include <unistd.h>
}

namespace
{
	// Don't export any of this
	// Open the device on loading, and close on unloading.
	struct fd_guard
	{
		fd_guard(const char *path)
			: fd { open(path, O_RDWR | O_CLOEXEC | O_NONBLOCK) }
		{}
		~fd_guard() { close(fd); }

		int fd;
	};

	fd_guard global_guard { PLUTONIUM_DBG_PATH };

	// Abstract the file descriptor away
	template <typename T>
	int send_ioctl(unsigned long request, T *argument)
	{
		return ::ioctl(
			::global_guard.fd,
			request,
			reinterpret_cast<char *>(argument)
		);
	}
}

// Actual functionality
namespace PLUTONIUM_DBG_NS
{
	int continue_thread(pid_t tid)
	{
		ioctl_tid_or_tgid argument { tid, ioctl_tid_or_tgid::TID };
		return ::send_ioctl(IOCTL_CONTINUE, &argument);
	}

	int continue_process(pid_t tgid)
	{
		ioctl_tid_or_tgid argument { tgid, ioctl_tid_or_tgid::TGID };
		return ::send_ioctl(IOCTL_CONTINUE, &argument);
	}

	int suspend_thread(pid_t tid)
	{
		ioctl_tid_or_tgid argument { tid, ioctl_tid_or_tgid::TID };
		return ::send_ioctl(IOCTL_SUSPEND, &argument);
	}

	int suspend_process(pid_t tgid)
	{
		ioctl_tid_or_tgid argument { tgid, ioctl_tid_or_tgid::TGID };
		return ::send_ioctl(IOCTL_SUSPEND, &argument);
	}

	int install_breakpoint(pid_t tgid, addr_t address)
	{
		ioctl_breakpoint_identifier argument { tgid, address };
		return ::send_ioctl(IOCTL_INSTALL_BREAKPOINT, &argument);
	}

	int remove_breakpoint(pid_t tgid, addr_t address)
	{
		ioctl_breakpoint_identifier argument { tgid, address };
		return ::send_ioctl(IOCTL_REMOVE_BREAKPOINT, &argument);
	}

	int thread_set_stepping(pid_t tid, bool step)
	{
		ioctl_flag argument { tid, step };
		return ::send_ioctl(IOCTL_SET_STEP, &argument);
	}

	int set_event_mask(pid_t tgid, int mask)
	{
		ioctl_flag argument { tgid, mask };
		return ::send_ioctl(IOCTL_SET_EVENT_MASK, &argument);
	}

	ssize_t wait(ioctl_event *event_buffer, size_t buffer_size)
	{
		ioctl_enumeration argument { 0, reinterpret_cast<addr_t>(event_buffer), buffer_size, 0 };
		int error = ::send_ioctl(IOCTL_WAIT, &argument);
		if (error < 0)
			return error;
		return argument.size;
	}

	ssize_t wait_for(pid_t tid, ioctl_event *event_buffer, size_t buffer_size)
	{
		ioctl_enumeration argument { tid, reinterpret_cast<addr_t>(event_buffer), buffer_size, 0 };
		int error = ::send_ioctl(IOCTL_WAIT_FOR, &argument);
		if (error < 0)
			return error;
		return argument.size;
	}

	ssize_t events(ioctl_event *event_buffer, size_t buffer_size)
	{
		ioctl_enumeration argument { 0, reinterpret_cast<addr_t>(event_buffer), buffer_size, 0 };
		int error = ::send_ioctl(IOCTL_EVENTS, &argument);
		if (error < 0)
			return error;
		return argument.size;
	}

	ssize_t status(pid_t *tid_buffer, size_t buffer_size)
	{
		ioctl_enumeration argument { 0, reinterpret_cast<addr_t>(tid_buffer), buffer_size, 0 };
		int error = ::send_ioctl(IOCTL_STATUS, &argument);
		if (error < 0)
			return error;
		return argument.size;
	}

	ssize_t enumerate_threads(pid_t tgid, pid_t *tid_buffer, size_t buffer_size)
	{
		ioctl_enumeration argument { tgid, reinterpret_cast<addr_t>(tid_buffer), buffer_size, 0 };
		int error = ::send_ioctl(IOCTL_STATUS, &argument);
		if (error < 0)
			return error;
		return argument.size;
	}

	int suspension_reason(pid_t tid)
	{
		ioctl_flag argument { tid, 0 };
		int error = ::send_ioctl(IOCTL_SUSPEND_REASON, &argument);
		if (error < 0)
			return error;
		return argument.value;
	}

	int read_memory(pid_t tgid, addr_t address, unsigned char *buffer, size_t size)
	{
		ioctl_cpy argument { tgid, address, reinterpret_cast<addr_t>(buffer), size };
		return ::send_ioctl(IOCTL_READ_MEMORY, &argument);
	}

	int write_memory(pid_t tgid, addr_t address, const unsigned char *buffer, size_t size)
	{
		ioctl_cpy argument { tgid, address, reinterpret_cast<addr_t>(buffer), size };
		return ::send_ioctl(IOCTL_WRITE_MEMORY, &argument);
	}

	ssize_t read_registers(pid_t tid, int request_type, unsigned char *buffer, size_t size)
	{
		ioctl_cpy argument { tid, static_cast<addr_t>(request_type), reinterpret_cast<addr_t>(buffer), size };
		int error = ::send_ioctl(IOCTL_READ_REGISTERS, &argument);
		if (error < 0)
			return error;
		return argument.size;
	}

	int write_registers(pid_t tid, int request_type, const unsigned char *buffer, size_t size)
	{
		ioctl_cpy argument { tid, static_cast<addr_t>(request_type), reinterpret_cast<addr_t>(buffer), size };
		return ::send_ioctl(IOCTL_READ_REGISTERS, &argument);
	}

	int read_auxv(pid_t tid, unsigned char *buffer, size_t size)
	{
		ioctl_cpy argument { tid, 0, reinterpret_cast<addr_t>(buffer), size };
		return ::send_ioctl(IOCTL_READ_AUXV, &argument);
	}

	int cancel_signal(pid_t tid)
	{
		ioctl_tid_or_tgid argument { tid, ioctl_tid_or_tgid::TID };
		return ::send_ioctl(IOCTL_CANCEL_SIGNAL, &argument);
	}
}
