import ctypes
import fcntl
import os
import struct


# IOCTL commands
class ioctl:
    # See <uapi/asm-generic/ioctl.h>
    NONE = 0
    W    = 1
    R    = 2
    RW   = 3

    def __init__(self, code, number, rw, size_of_arg = 0):
        self.code          = code
        self.number        = number
        self.direction     = rw
        self.argument_size = size_of_arg

        # See <uapi/asm-generic/ioctl.h>
        self.command_id    = (rw << (8 + 8 + 14)) | (size_of_arg << (8 + 8)) | (code << 8) | number

    def send(self, fd, message = 0):
        """Sends the IOCTL. The message parameter must be mutable (bytearray or ctypes)"""
        return fcntl.ioctl(fd, self.command_id, message)


# Message types (see types.h)
class messages:
    class ioctl_tid_or_tgid(ctypes.Structure):
        _fields_ = [("id",   ctypes.c_uint),
                    ("type", ctypes.c_int)]

    class ioctl_enumeration(ctypes.Structure):
        _fields_ = [("target",    ctypes.c_uint),
                    ("buffer",    ctypes.c_void_p),
                    ("size",      ctypes.c_size_t),
                    ("available", ctypes.c_size_t)]

    class ioctl_breakpoint_identifier(ctypes.Structure):
        _fields_ = [("target",  ctypes.c_uint),
                    ("address", ctypes.c_void_p)]

    class ioctl_cpy(ctypes.Structure):
        _fields_ = [("target", ctypes.c_uint),
                    ("which",  ctypes.c_void_p),
                    ("buffer", ctypes.c_void_p),
                    ("size",   ctypes.c_size_t)]

    class ioctl_flag(ctypes.Structure):
        _fields_ = [("target", ctypes.c_uint),
                    ("value",  ctypes.c_int)]


    class ioctl_event(ctypes.Structure):
        class event_data(ctypes.Union):
            class __clone(ctypes.Structure):
                _fields_ = [("new_task_tid", ctypes.c_uint),
                            ("clone_flags",  ctypes.c_ulong)]
            class __exec(ctypes.Structure):
                _fields_ = [("calling_tid",  ctypes.c_uint),
                            ("filename", ctypes.c_char * (os.statvfs("/").f_namemax + 1))]
            _fields_ = [("suspension_reason", ctypes.c_int),
                        ("exit_code",         ctypes.c_int),
                        ("signal",            ctypes.c_int),
                        ("clone_data",        __clone),
                        ("exec_data",         __exec)]
        _fields_ = [("event",  ctypes.c_int),
                    ("victim", ctypes.c_uint),
                    ("data",   event_data)]


# List of IOCTL commands
class commands:
    cmd_continue       = ioctl(ord("@"),  0, ioctl.W, ctypes.sizeof(messages.ioctl_tid_or_tgid))
    cmd_suspend        = ioctl(ord("@"),  1, ioctl.W, ctypes.sizeof(messages.ioctl_tid_or_tgid))
    cmd_install_bp     = ioctl(ord("@"), 10, ioctl.W, ctypes.sizeof(messages.ioctl_breakpoint_identifier))
    cmd_remove_bp      = ioctl(ord("@"), 11, ioctl.W, ctypes.sizeof(messages.ioctl_breakpoint_identifier))
    cmd_set_step       = ioctl(ord("@"), 20, ioctl.W, ctypes.sizeof(messages.ioctl_flag))
    cmd_set_event_mask = ioctl(ord("@"), 30, ioctl.W, ctypes.sizeof(messages.ioctl_flag))
    cmd_cancel_signal  = ioctl(ord("@"), 40, ioctl.W, ctypes.sizeof(messages.ioctl_tid_or_tgid))
    cmd_wait           = ioctl(ord("@"),  0, ioctl.RW, ctypes.sizeof(messages.ioctl_enumeration))
    cmd_wait_for       = ioctl(ord("@"),  1, ioctl.RW, ctypes.sizeof(messages.ioctl_enumeration))
    cmd_events         = ioctl(ord("@"),  2, ioctl.RW, ctypes.sizeof(messages.ioctl_enumeration))
    cmd_status         = ioctl(ord("@"), 10, ioctl.RW, ctypes.sizeof(messages.ioctl_enumeration))
    cmd_enum_threads   = ioctl(ord("@"), 11, ioctl.RW, ctypes.sizeof(messages.ioctl_enumeration))
    cmd_reason         = ioctl(ord("@"), 12, ioctl.RW, ctypes.sizeof(messages.ioctl_flag))
    cmd_read_mem       = ioctl(ord("@"), 20, ioctl.RW, ctypes.sizeof(messages.ioctl_cpy))
    cmd_write_mem      = ioctl(ord("@"), 21, ioctl.RW, ctypes.sizeof(messages.ioctl_cpy))
    cmd_read_auxv      = ioctl(ord("@"), 22, ioctl.RW, ctypes.sizeof(messages.ioctl_cpy))
    cmd_read_regs      = ioctl(ord("@"), 30, ioctl.RW, ctypes.sizeof(messages.ioctl_cpy))
    cmd_write_regs     = ioctl(ord("@"), 31, ioctl.RW, ctypes.sizeof(messages.ioctl_cpy))


# Actual client
class debugger:
    # Constants (see types.h)
    NOT_SUSPENDED          = 0
    SUSPEND_EXPLICIT       = 1
    SUSPEND_ON_BREAK       = 2
    SUSPEND_ON_SINGLE_STEP = 3
    SUSPEND_ON_EXIT        = 4
    SUSPEND_ON_CLONE       = 5
    SUSPEND_ON_EXEC        = 6
    SUSPEND_ON_SIGNAL      = 7

    EVENT_SUSPEND =  1
    EVENT_EXIT    =  2
    EVENT_CLONE   =  4
    EVENT_EXEC    =  8
    EVENT_SIGNAL  = 16

    ALL_EVENTS = EVENT_SUSPEND | EVENT_EXIT | EVENT_CLONE | EVENT_EXEC | EVENT_SIGNAL

    # IOCTL parsing
    @staticmethod
    def _parse_event(ioctl_evt):
        evt = {"event": ioctl_evt.event, "victim": ioctl_evt.victim}
        if evt["event"] == debugger.EVENT_SUSPEND:
            evt["data"] = ioctl_evt.data.suspension_reason
        elif evt["event"] == debugger.EVENT_EXIT:
            evt["data"] = ioctl_evt.data.exit_code
        elif evt["event"] == debugger.EVENT_CLONE:
            evt["data"] = { "new_task_tid": ioctl_evt.data.clone_data.new_task_tid,
                            "clone_flags":  ioctl_evt.data.clone_data.clone_flags }
        elif evt["event"] == debugger.EVENT_EXEC:
            evt["data"] = { "calling_tid":  ioctl_evt.data.exec_data.calling_tid,
                            "filename": ioctl_evt.data.exec_data.filename }
        elif evt["event"] == debugger.EVENT_SIGNAL:
            evt["data"] = ioctl_evt.data.signal
        else:
            raise KeyError("Unknown event ID: {}".format(evt["event"]))
        return evt

    # Actual client commands
    def __init__(self):
        self.device = open("/dev/debugging")
    def wait(self):
        buf_size = 256
        events = []
        while buf_size > 0:
            buf = ctypes.create_string_buffer(buf_size * ctypes.sizeof(messages.ioctl_event))
            info = messages.ioctl_enumeration(0, ctypes.c_void_p(ctypes.addressof(buf)), buf_size, 0)
            commands.cmd_wait.send(self.device, info)
            result_array = ctypes.cast(buf, ctypes.POINTER(messages.ioctl_event))
            events.extend(debugger._parse_event(result_array[i]) for i in range(info.size))
            buf_size = 2 * info.available
        return events
    def wait_for(self, tid):
        buf_size = 256
        events = []
        while buf_size > 0:
            buf = ctypes.create_string_buffer(buf_size * ctypes.sizeof(messages.ioctl_event))
            info = messages.ioctl_enumeration(tid, ctypes.c_void_p(ctypes.addressof(buf)), buf_size, 0)
            commands.cmd_wait_for.send(self.device, info)
            result_array = ctypes.cast(buf, ctypes.POINTER(messages.ioctl_event))
            events.extend(debugger._parse_event(result_array[i]) for i in range(info.size))
            buf_size = 2 * info.available
        return events
    def events(self):
        buf_size = 256
        events = []
        while buf_size > 0:
            buf = ctypes.create_string_buffer(buf_size * ctypes.sizeof(messages.ioctl_event))
            info = messages.ioctl_enumeration(0, ctypes.c_void_p(ctypes.addressof(buf)), buf_size, 0)
            commands.cmd_events.send(self.device, info)
            result_array = ctypes.cast(buf, ctypes.POINTER(messages.ioctl_event))
            events.extend(debugger._parse_event(result_array[i]) for i in range(info.size))
            buf_size = 2 * info.available
        return events
    def continue_thread(self, tid):
        info = messages.ioctl_tid_or_tgid(tid, 0)
        commands.cmd_continue.send(self.device, info)
    def continue_process(self, tgid):
        info = messages.ioctl_tid_or_tgid(tgid, 1)
        commands.cmd_continue.send(self.device, info)
    def suspend_thread(self, tid):
        info = messages.ioctl_tid_or_tgid(tid, 0)
        commands.cmd_suspend.send(self.device, info)
    def suspend_process(self, tgid):
        info = messages.ioctl_tid_or_tgid(tgid, 1)
        commands.cmd_suspend.send(self.device, info)
    def install_breakpoint(self, tgid, address):
        info = messages.ioctl_breakpoint_identifier(tgid, address)
        commands.cmd_install_bp.send(self.device, info)
    def remove_breakpoint(self, tgid, address):
        info = messages.ioctl_breakpoint_identifier(tgid, address)
        commands.cmd_remove_bp.send(self.device, info)
    def thread_set_stepping(self, tid, state):
        info = messages.ioctl_flag(tid, 1 if state else 0)
        commands.cmd_set_step.send(self.device, info)
    def set_event_mask(self, tgid, mask):
        info = messages.ioctl_flag(tgid, mask)
        commands.cmd_set_event_mask.send(self.device, info)
    def status(self):
        buf_size = 256
        while True:
            buf = ctypes.create_string_buffer(buf_size * ctypes.sizeof(ctypes.c_uint))
            info = messages.ioctl_enumeration(-1, ctypes.c_void_p(ctypes.addressof(buf)), buf_size, 0)
            commands.cmd_status.send(self.device, info)
            if info.available <= buf_size:
                return list(struct.unpack("I" * info.available, buf.raw[:(info.available * ctypes.sizeof(ctypes.c_uint))]))
            else:
                buf_size *= 2
    def enumerate_threads(self, tgid):
        buf_size = 256
        while True:
            buf = ctypes.create_string_buffer(buf_size * ctypes.sizeof(ctypes.c_uint))
            info = messages.ioctl_enumeration(tgid, ctypes.c_void_p(ctypes.addressof(buf)), buf_size, 0)
            commands.cmd_enum_threads.send(self.device, info)
            if info.available <= buf_size:
                return list(struct.unpack("I" * info.available, buf.raw[:(info.available * ctypes.sizeof(ctypes.c_uint))]))
            else:
                buf_size *= 2
    def suspension_reason(self, tid):
        info = messages.ioctl_flag(tid, 0);
        commands.cmd_reason.send(self.device, info)
        return int(info.value)
    def read_memory(self, tgid, address, size):
        buf = ctypes.create_string_buffer(size)
        info = messages.ioctl_cpy(tgid, address, ctypes.c_void_p(ctypes.addressof(buf)), size)
        commands.cmd_read_mem.send(self.device, info)
        return bytes(buf.raw)
    def read_auxv(self, tgid):
        # XXX: Pretty arbitrary, enough space to hold auxiliary vector
        size = 0x400
        buf = ctypes.create_string_buffer(size)
        # XXX: address argument is ignored by read_auxv
        info = messages.ioctl_cpy(tgid, 0, ctypes.c_void_p(ctypes.addressof(buf)), size)
        l = commands.cmd_read_auxv.send(self.device, info)
        return bytes(buf.raw)[:l]
    def write_memory(self, tgid, address, contents):
        buf = ctypes.create_string_buffer(contents)
        info = messages.ioctl_cpy(tgid, address, ctypes.c_void_p(ctypes.addressof(buf)), len(contents))
        commands.cmd_write_mem.send(self.device, info)
    def read_registers(self, tid, request_type):
        buf_size = 1024
        while True:
            buf = ctypes.create_string_buffer(buf_size)
            info = messages.ioctl_cpy(tid, request_type, ctypes.c_void_p(ctypes.addressof(buf)), buf_size)
            commands.cmd_read_regs.send(self.device, info)
            if info.size <= buf_size:
                return buf.raw[:info.size]
            else:
                buf_size *= 2
    def write_registers(self, tid, request_type, bits):
        buf = ctypes.create_string_buffer(bits)
        info = messages.ioctl_cpy(tid, request_type, ctypes.c_void_p(ctypes.addressof(buf)), len(bits))
        commands.cmd_write_regs.send(self.device, info)
    def cancel_signal(self, tid):
        info = messages.ioctl_tid_or_tgid(tid, 0)
        commands.cmd_cancel_signal.send(self.device, info)
