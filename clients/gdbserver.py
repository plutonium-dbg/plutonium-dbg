#!/usr/bin/env python3

#   gdbserver.py - Use plutonium-dbg with GDB!
#   Copyright (C) 2018 Philipp "PhiK" Klocke, Tobias Holl
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; either version 2
#   of the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import argparse
import ctypes
import errno
import logging
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import os

from binascii import hexlify, unhexlify
from plutonium_dbg import debugger
from subprocess import check_output

# globals
# TODO create hierarchy/class-structure for encapsulation
GDB_SIGNAL_TRAP = 5
PACKET_SIZE = 4096
log = None
mod = debugger()
tgid = 0
no_ack_mode = False

# A list of tuples describing the debuggee's auxiliary vector (man 3 getauxval)
auxv = []
# 8 for 64 bit deubggees, 4 otherwise
ptrsz = 0
# helper for struct.[un]pack: "Q" for 64 bit debuggees, "I" otherwise
ptrspec = ""
# helper for struct.[un]pack: "<" for little endian debuggees, ">" otherwise
bitness = ""

class pt_regs(ctypes.Structure):
    _fields_ = [("r15",   ctypes.c_ulong),
                ("r14",   ctypes.c_ulong),
                ("r13",   ctypes.c_ulong),
                ("r12",   ctypes.c_ulong),
                ("bp",    ctypes.c_ulong),
                ("bx",    ctypes.c_ulong),
                ("r11",   ctypes.c_ulong),
                ("r10",   ctypes.c_ulong),
                ("r9",    ctypes.c_ulong),
                ("r8",    ctypes.c_ulong),
                ("ax",    ctypes.c_ulong),
                ("cx",    ctypes.c_ulong),
                ("dx",    ctypes.c_ulong),
                ("si",    ctypes.c_ulong),
                ("di",    ctypes.c_ulong),
                ("o_ax",  ctypes.c_ulong),
                ("ip",    ctypes.c_ulong),
                ("cs",    ctypes.c_ulong),
                ("flags", ctypes.c_ulong),
                ("sp",    ctypes.c_ulong),
                ("ss",    ctypes.c_ulong),
                ("fs_b",  ctypes.c_ulong),
                ("gs_b",  ctypes.c_ulong),
                ("ds",    ctypes.c_ulong),
                ("es",    ctypes.c_ulong),
                ("fs",    ctypes.c_ulong),
                ("gs",    ctypes.c_ulong)]


def try_ignore_eexist(f, *args):
    try:
        return f(*args)
    except IOError as e:
        if errno.EEXIST != e.errno:
            raise
    return None


def checksum(data):
    """calculates checksum of data (as bytes)"""
    return sum(data) & 0xff


def receive(conn):
    """Receive a packet from a GDB client"""

    # ready = select.select([conn], [], [], 0) # will never block
    ready = select.select([conn], [], [], 1) # wait 1s
    if len(ready[0]) == 0:
        return b""

    packet = conn.recv(PACKET_SIZE)
    if packet != b'' and packet != b'+':
        log.info("<- %r" % repr(packet))
    return packet


def parse(packet):
    # TODO: use ply or similar?


    # TODO: if first character is 'X', the $ and # might be from the payload.
    # Since we do not handle 'X' packets yet, we can ignore this.

    if packet == b"":
        return b""

    log.info("parsing " + repr(packet))

    if packet == b'\x03':
        return b"Ctrl+C"

    if packet == b'+':
        return b""

    if packet == b'-':
        log.info("Received retransmit-request")
        return b"-"

    # TODO: this assumes no packet 'overlap'
    _, packet = packet.split(b'$', 1)
    data, chk = packet.split(b'#', 1)

    chk = int(chk[:2], 16)

    if chk != checksum(data):
        log.warning("Ignoring invalid checksum " + str(chk) + " for: " + str(data))
        return b""

    return data

def _binary_escape(bs):

    res = b""
    for i, b in enumerate(bs):
        if b in [ b"#", b"$", b"}", b"*" ]:
            res += b"}" + (b ^ 0x20)
        else:
            res += bytes([b])

    return res


def send(conn, msg):
    """Send a packet to the GDB client
    msg can be string or bytestring
    """

    # XXX: I feel soooooo bad for doing this :(
    if type(msg) == bytes:
        msg_b = _binary_escape(msg)
    else:
        msg_b = _binary_escape(msg.encode('ascii'))

    chk = hex(checksum(msg_b))[2:].rjust(2, "0").encode('ascii')
    send_raw(conn, b'$' + msg_b + b'#' + chk)


def send_raw(conn, msg):
    if msg != '+':
        log.info('-> %r' % repr(msg))
    conn.sendall(msg)

def _general_set(request):
    global no_ack_mode
    if request.startswith('StartNoAckMode'):
        no_ack_mode = True
        return 'OK'

    return ''


def _general_query(request):
    if request.startswith('Supported'):
        return _q_supported(request)
    if request.startswith('Attached'):
        # not necessary when using launcher, since victim is already suspended
        # for t in mod.enumerate_threads(tgid):
        #   mod.suspend_thread(t)
        return '1' # to indicate that we attached to a running process
    if request == 'C':
        return 'QC' + hex(tgid)[2:]
    if request.startswith('Xfer:auxv:read'):
        return _q_auxv_read(request)
    return ""


def _q_supported(request):
    def assert_support(x):
        if not x in request:
            log.error("GDB Client does not support" + x + ". Aborting")
            os.kill(tgid, signal.SIGKILL)
            exit(0)

    supported = ['no-resumed+', 'swbreak+']
    for x in supported:
        assert_support(x)

    # add features only supported by the server
    supported.extend(['QStartNoAckMode+', 'qXfer:auxv:read+'])

    return 'PacketSize=%x;' % PACKET_SIZE + ';'.join(supported)


def _q_auxv_read(request):
    log.info('Received a "read auxiliary vector" command')

    off, l = map(lambda x: int(x, 16), request.split('::')[1].split(','))
    print(off, l)

    tmp = b''
    for a in auxv:
        tmp += b''.join(map(lambda x: struct.pack(endness + ptrspec, x), a))

    # auxval HAS to end with two 0 entries
    tmp += b"\x00" * (ptrsz * 2)

    # pad to match requested length
    res = tmp[off:][:l]

    return b"l" + res

def _memory_read(request):
    # we don't need to loop over tid's here, since threads share memory space anyways.
    addr, size = request.split(',')
    addr = int(addr, 16)
    size = int(size, 16)
    log.info('Received a "read memory" command (@%#.8x : %d bytes)' % (addr, size))

    try:
        s = mod.read_memory(tgid, addr, size)
    except IOError as e:
        return "E%02d" % e.errno

    return hexlify(s).decode('ascii')


def _memory_write(request):
    addr, _ = request.split(',')
    size, val = _.split(':')
    addr = int(addr, 16)
    size = int(size, 16)
    val = unhexlify(val)
    assert size == len(val)
    log.info('Received a "write memory" command (@%#.8x : %d bytes : %s value)' % (addr, size, hexlify(val)))
    mod.write_memory(tgid, addr, val)
    return 'OK'


def _breakpoint_set(request):
    num, addr, stuff = request.split(',')
    if num != '0':
        log.error("Can't handle breakpoint type: " + num)
        return 'E01'
    num = int(num, 16)
    addr = int(addr, 16)
    stuff = int(stuff, 16) # use?
    log.info('Received a "set breakpoint" command (%d : @%#.8x : %d)' % (num, addr, stuff))
    mod.install_breakpoint(tgid, addr)
    return 'OK'


def _breakpoint_unset(request):
    num, addr, stuff = request.split(',')
    if num != '0':
        log.error("Can't handle breakpoint type: " + num)
        return 'E01'
    num = int(num, 16)
    addr = int(addr, 16)
    stuff = int(stuff, 16) # use?
    log.info('Received a "remove breakpoint" command (%d : @%#.8x : %d)' % (num, addr, stuff))
    mod.remove_breakpoint(tgid, addr)
    return 'OK'


def _single_step(request):
    log.info('Received a "single step" command')
    for tid in get_active_tids('s'):
        try_ignore_eexist(mod.suspend_thread, tid)
        try_ignore_eexist(mod.thread_set_stepping, tid, True)
        mod.continue_thread(tid)
    return None


def _continue(request):
    log.info('Received a "continue" command')
    for tid in get_active_tids('c'):
        try:
            try_ignore_eexist(mod.thread_set_stepping, tid, False)
        except IOError as e:
            if errno.ENOENT != e.errno:
                raise
        mod.continue_thread(tid)
    return None


def _thread_alive(request):
    # TODO: workaround, maybe the tid is already taken by another thread
    threads = mod.enumerate_threads(tgid)
    if int(request, 16) in threads:
        return "OK"
    else:
        return "E01" # whatever error


def _registers_read(request):
    ret = b''
    for tid in get_active_tids('g'):
        s = mod.read_registers(tid, 1)
        r = pt_regs()
        ctypes.memmove(ctypes.addressof(r), s, ctypes.sizeof(r))
        regs = [r.ax, r.bx, r.cx, r.dx, r.si, r.di, r.bp, r.sp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.ip]
        eflags = r.flags
        segs = [r.cs, r.ss, r.ds, r.es, r.fs, r.gs]
        s = b''
        for reg in regs:
            s += hexlify(struct.pack('<Q', reg))
        s += hexlify(struct.pack('<L', eflags))
        for seg in segs:
            s += hexlify(struct.pack('<L', seg))
        ret += s
    return ret.decode('ascii')


def _stop_reason(request):
    # FIXME for now just send trap-signal.
    # actually the events have to be handled here
    return 'S%.2x' % GDB_SIGNAL_TRAP


active_tids = {}

def _thread_set(request):
    global active_tids

    affected_op = request[0]
    tid = int(request[1:], 16)
    log.info("Received a set-thread packet for thread %d and operation %c" % (tid, affected_op))
    if tid == -1:
        # -1 = all threads
        log.info("tgid = " + repr(tgid))
        active_tids[affected_op] = mod.enumerate_threads(tgid)
        return 'OK'
    elif tid == 0:
        # 0 = arbitrary process/thread
        log.info("Using tgid as arbitrary process id")
        tid = tgid
    active_tids[affected_op] = [tid]
    return 'OK'


def get_active_tids(op_type):
    """returns tids that the op_type operation should affect"""
    global active_tids
    if op_type in active_tids:
        return active_tids[op_type]
    return [tgid]

handlers = {
    'q' : _general_query,
    'Q' : _general_set,
    'm' : _memory_read,
    'M' : _memory_write,
    'z' : _breakpoint_unset,
    'Z' : _breakpoint_set,
    'g' : _registers_read,
#   'G' : _registers_write,
    '?' : _stop_reason,
    's' : _single_step,
    'c' : _continue,
    'T' : _thread_alive,
    'H' : _thread_set
}


def main_loop(conn):
    global no_ack_mode
    events = []
    last_packet = ""
    while True:
        # handle packets
        packet = parse(receive(conn)).decode('ascii')
        if packet == "-":
            log.info('Resending last packet')
            send(conn, last_packet)
            continue
        if packet != "":
            if no_ack_mode == False:
                send_raw(conn, b'+')
            if(packet == "Ctrl+C"):
                mod.suspend_process(tgid)
                continue
            command, data = packet[0], packet[1:]
            try:
                if command in handlers.keys():
                    response = handlers[command](data)
                    if response is None:
                        continue # rather continue with handle events, needs slight refactoring
                    send(conn, response)
                    last_packet = response
                else:
                    log.debug('Ignoring packet due to missing handler for ' + command)
                    send(conn, "")
                    last_packet = ""
            except KeyboardInterrupt:
                send(conn, 'E01')
                last_packet = 'E01'

        # handle events
        events.extend(mod.events())
        handled_events = []
        for event in events:
            if event['event'] == mod.EVENT_SUSPEND:
                if event['data'] == 2 or event['data'] == 3:
                    send(conn, 'T' + str(GDB_SIGNAL_TRAP).rjust(2, '0') + 'thread:' + hex(event['victim'])[2:] + ';')
                else:
                    send(conn, 'S01')
                handled_events.append(event)
            elif event['event'] == mod.EVENT_EXIT:
                # TODO: handle this appropriately
                pass
            else:
                log.info('Not handling event: ' + repr(event))
                handled_events.append(event)
        events = [e for e in events if not e in handled_events]

def _get_auxv():
    """ This retrieves the "auxiliary vector", a very useful (man 3 getauxval)
    datastructure from the debuggee. As the layout of the auxiliary vector
    is key, value alike, we also use this to determine the debugees bitness and
    endianness. """
    global log
    global tgid
    global ptrsz
    global ptrspec
    global endness

    i = 0
    res = []

    AT_MAX = 0x40

    mem = mod.read_auxv(tgid)

    # TODO: It would be nice to know guest bitness and endianness here.
    # For now we have to live with this hack.
    if all(map(lambda x: x < AT_MAX, struct.unpack("<10I", mem[:10*4])[2::2])):
        ptrsz = 4
        endness = "<"
    elif all(map(lambda x: x < AT_MAX, struct.unpack("<10Q", mem[:10*8])[2::2])):
        ptrsz = 8
        endness = "<"
    elif all(map(lambda x: x < AT_MAX, struct.unpack(">10I", mem[:10*4])[2::2])):
        ptrsz = 4
        endness = ">"
    elif all(map(lambda x: x < AT_MAX, struct.unpack(">10I", mem[:10*8])[2::2])):
        ptrsz = 8
        endness = ">"
    else:
        log.warn("Unable to fetch auxiliary vector. Unknown debuggee bitness and endianness?")
        return res

    ptrspec = "I" if ptrsz == 4 else "Q"

    while 2 * i * ptrsz < len(mem):
        key, val = struct.unpack(endness + "2" + ptrspec, mem[2*i*ptrsz:][:2*ptrsz])
        if key == val == 0:
            break

        res.append((key, val))

        i += 1

    return res


def main(tcp_port, unix_socket, victim_command):
    global log
    global tgid
    global auxv

    logging.basicConfig(level = logging.DEBUG)
    log = logging.getLogger('')

    if tcp_port is not None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', tcp_port))
    else:
        if os.path.exists(unix_socket):
            print("Error: socket file", unix_socket, "exists!")
            exit(-1)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(unix_socket)


    tgid = subprocess.Popen(["./launch"] + victim_command).pid
    mod.set_event_mask(tgid, mod.EVENT_EXEC)
    time.sleep(1) # TODO: get feedback from launch program
    os.kill(tgid, signal.SIGUSR1) # signal that we're set up
    mod.wait() # wait for exec event
    mod.set_event_mask(tgid, mod.EVENT_SUSPEND)

    if tcp_port is not None:
        log.info('listening on :%d' % tcp_port)
    else:
        log.info('listening on ' + unix_socket)
    sock.listen(1)
    conn, addr = sock.accept()
    conn.setblocking(0)
    log.info('connected')

    auxv = _get_auxv()

    try:
        main_loop(conn)
    finally:
        conn.close()
        sock.close()


if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This program requires python3!")
        exit(-1)

    parser = argparse.ArgumentParser(description="Let GDB debug a victim with plutonium-dbg")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--tcp', help="Use TCP with given port", metavar='PORT', type=int)
    group.add_argument('--unix', help="Use Unix Domain Socket with given name", type=str)
    parser.add_argument('command', help="Command to start the victim", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    main(args.tcp, args.unix, args.command)
