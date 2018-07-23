#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#     gdbserver.py - Use plutonium-dbg with GDB!
#     Copyright (C) 2013 Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
#     Copyright (C) 2018 Philipp "PhiK" Klocke, Tobias Holl
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.


from __future__ import absolute_import
from __future__ import print_function
from __future__ import division


import sys
import socket
import logging
import struct
import subprocess
import ctypes
import errno
import signal
import os

from binascii import hexlify, unhexlify

from plutonium_dbg import debugger

GDB_SIGNAL_TRAP = 5

PACKET_SIZE = 4096


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


def checksum(data):
    checksum = 0
    for c in data:
        checksum += ord(c)
    return checksum & 0xff


def unpack_thread(x):
    if x == "-1":
        return -1
    # TODO easier way?
    x = x.rjust(8, '0')
    x = unhexlify(x)
    x = struct.unpack('>I', x)[0]
    return x

# Code a bit inspired from http://mspgcc.cvs.sourceforge.net/viewvc/mspgcc/msp430simu/gdbserver.py?revision=1.3&content-type=text%2Fplain
class GDBClientHandler(object):
    def __init__(self, clientsocket, tgid):
        self.clientsocket = clientsocket
        self.netin = clientsocket.makefile('r')
        self.netout = clientsocket.makefile('w')
        self.log = logging.getLogger('gdbclienthandler')
        self.last_pkt = None
        self.mod = debugger()
        self.tgid = tgid
        self.active_tid = self.tgid

    def close(self):
        '''End of story!'''
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()
        os.kill(self.tgid, signal.SIGTERM)
        self.log.info('closed')

    def run(self):
        '''Some doc about the available commands here:
            * http://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html#id3081722
            * http://git.qemu.org/?p=qemu.git;a=blob_plain;f=gdbstub.c;h=2b7f22b2d2b8c70af89954294fa069ebf23a5c54;hb=HEAD
            * http://git.qemu.org/?p=qemu.git;a=blob_plain;f=target-i386/gdbstub.c;hb=HEAD'''
        self.log.info('client loop ready...')
        while self.receive() == 'Good':
            pkt = self.last_pkt
            self.log.debug('receive(%r)' % pkt)
            # Each packet should be acknowledged with a single character. '+' to indicate satisfactory receipt
            self.send_raw('+')

            def handle_general_query(subcmd):
                '''
                subcmd Supported: https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#qSupported
                Report the features supported by the RSP server. As a minimum, just the packet size can be reported.
                '''
                if subcmd.startswith('Supported'):
                    self.log.info('Received qSupported command')

                    def assert_support(x):
                        if not x in subcmd:
                            self.log.error("GDB Client does not support" + x + ". Aborting")
                            os.kill(self.tgid, signal.SIGTERM)
                            exit(0)

                    assert_support('no-resumed')
                    assert_support('swbreak')

                    self.send('PacketSize=%x;no-resumed+;swbreak+' % PACKET_SIZE)
                    # TODO: support true multiprocessing including vCont
                    # assert_support('multiprocess')
                    # self.send('PacketSize=%x;no-resumed+;swbreak+;multiprocess+' % PACKET_SIZE)
                elif subcmd.startswith('Attached'):
                    # TODO: somwhere it said that it's not necessary to pause everything here, because gdb will do it on it's own.
                    # for now we will just stick with it.
                    # FIXME: this will break the protocol when we wait for too long until we reply back to gdb. Thus we'll need to write our own execve launcher.
                    self.log.info('Received qAttached command')
                    # https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
                    self.mod.set_event_mask(self.tgid, self.mod.EVENT_SUSPEND) # Enable only suspend event
                    self.mod.suspend_process(self.tgid)
                    events = self.mod.wait()
                    self.log.warning('wait() returned the following events: %s' % str(events))
                    self.send('1')
                elif subcmd.startswith('C'):
                    self.send('T%.2x;' % self.active_tid)
                elif subcmd.startswith('fThreadInfo'):
                    self.log.info("Received fThreadInfo")
                    threads = self.mod.enumerate_threads(self.tgid)
                    self.log.info("Got the following threads " + repr(threads))
                    answer = 'm' + ",".join([hexlify(struct.pack('>I', t)) for t in threads])
                    if len(answer) > PACKET_SIZE:
                        self.log.error("Answer is bigger than packet size\nWould need to implement splitting now!")
                    self.log.info("Replying with " + answer)
                    self.send(answer)
                elif subcmd.startswith('sThreadInfo'):
                    self.log.info("Received sThreadInfo, replying with End-Of-List")
                    self.send("l") # TODO: for now just assume that we don't have to split packets.
                elif subcmd.startswith('TStatus'):
                    self.log.info("Received qTStatus command")
                    self.send("T0;tnotrun:0") # we're not tracing anything. Probably we could ignore this package aswell
                elif subcmd.startswith('ThreadExtraInfo'):
                    self.log.info("Received qThreadExtraInfo command, replying with 'Unknown'")
                    self.send(hexlify("Unknown"))
                else:
                    self.log.error('This subcommand %r is not implemented in q' % subcmd)
                    self.send('')

            def handle_stop_reason(subcmd):
                """
                Happens when GDB asks why we stopped. Just answer TRAP
                """
                # FIXME: keep track of all active events here
                self.send('S%.2x' % GDB_SIGNAL_TRAP)

            def handle_get_regs(subcmd):
                if subcmd == '':
                    s = self.mod.read_registers(self.tgid, 1)
                    r = pt_regs()
                    ctypes.memmove(ctypes.addressof(r), s, ctypes.sizeof(r))
                    regs = [r.ax, r.bx, r.cx, r.dx, r.si, r.di, r.bp, r.sp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.ip]
                    eflags = r.flags
                    segs = [r.cs, r.ss, r.ds, r.es, r.fs, r.gs]
                    s = ''
                    for reg in regs:
                        s += hexlify(struct.pack('<Q', reg))
                    s += hexlify(struct.pack('<L', eflags))
                    for seg in segs:
                        s += hexlify(struct.pack('<L', seg))
                    self.send(s)

            def handle_mem_read(subcmd):
                addr, size = subcmd.split(',')
                addr = int(addr, 16)
                size = int(size, 16)
                # self.log.info('Received a "read memory" command (@%#.8x : %d bytes)' % (addr, size))
                try:
                    s = self.mod.read_memory(self.tgid, addr, size)
                except IOError as e:
                    self.send("E%02d" % e.errno)
                    return

                self.send(hexlify(s))

            def handle_mem_write(subcmd):
                """
                This is not actually required but one of the nice-to-have features.
                """
                addr, _ = subcmd.split(',')
                size, val = _.split(':')
                addr = int(addr, 16)
                size = int(size, 16)
                val = unhexlify(val)
                assert size == len(val)
                self.log.info('Received a "write memory" command (@%#.8x : %d bytes : %s value)' % (addr, size, hexlify(val)))
                self.mod.write_memory(self.tgid, addr, val)
                self.send('OK')
                # self.send("E01") if invalid. Actual Error Number is ignored

            def handle_single_step(subcmd):
                """
                Is this really necessary? Probably.
                """
                self.log.info('Received a "single step" command')

                try:
                    self.mod.suspend_thread(self.tgid)
                except IOError as e:
                    if errno.EEXIST != e.errno:
                        raise

                try:
                    self.mod.thread_set_stepping(self.tgid, True)
                except IOError as e:
                    if errno.EEXIST != e.errno:
                        raise

                self.mod.continue_thread(self.active_tid)
                _do_wait(self.active_tid)

            def handle_breakpoint_set(subcmd):
                num, addr, stuff = subcmd.split(',')
                num = int(num, 16)
                addr = int(addr, 16)
                stuff = int(stuff, 16)
                self.log.info('Received a "set breakpoint" command (%d : @%#.8x : %d)' % (num, addr, stuff))
                if num == 0: # 0 is software breakpoint
                    self.mod.install_breakpoint(self.tgid, addr)
                    self.send('OK')
                else:
                    self.log.error('Error: Breakpoint type %d not supported!' % num)
                    self.send('E01')

            def handle_breakpoint_remove(subcmd):
                num, addr, stuff = subcmd.split(',')
                num = int(num, 16) # use?
                addr = int(addr, 16)
                stuff = int(stuff, 16) # use?
                self.log.info('Received a "remove breakpoint" command (%d : @%#.8x : %d)' % (num, addr, stuff))
                if num == 0: # 0 is software breakpoint
                    self.mod.remove_breakpoint(self.tgid, addr)
                    self.send('OK')
                else:
                    self.log.error('Error: Breakpoint type %d not supported!' % num)
                    self.send('E01')

            def handle_continue(subcmd):
                self.log.info('Received a "continue" command')
                try:
                    self.mod.thread_set_stepping(self.active_tid, False)
                except IOError as e:
                    if e.errno != errno.ENOENT:
                        raise
                self.mod.continue_thread(self.active_tid)
                _do_wait()

            def handle_set_thread(subcmd):
                print(subcmd)
                op = subcmd[0]
                tid = unpack_thread(subcmd[1:])
                self.log.info("Received a set-thread packet for thread %d and operation %c" % (tid, op))
                self.log.warning("Ignoring op parameter")
                if tid == -1:
                    # -1 = all threads
                    self.log.warning("Assuming -1 means just tgid")
                    tid = self.tgid
                if tid == 0:
                    # 0 = arbitrary process/thread
                    self.log.info("Using tgid as arbitrary process id")
                    tid = self.tgid
                self.active_tid = tid
                self.send('OK')

            def handle_thread_alive(subcmd):
                # TODO: workaround, maybe the tid is already taken by another thread
                threads = self.mod.enumerate_threads(self.tgid)
                if unpack_thread(subcmd) in threads:
                    self.send("OK")
                else:
                    self.send("E01") # whatever error

            def _do_wait(tid=None):
                if tid is None:
                    events = self.mod.wait()
                else:
                    events = self.mod.wait_for(tid)
                self.log.warning('wait_for(%d) returned the following events: %s' % (self.tgid, str(events)))
                for evt in events:
                    if evt['event'] == self.mod.EVENT_EXIT:
                        if evt['victim'] == self.tgid:
                            self.send('W%.2x' % evt['data']) # signal process exit.
                            return
                        else:
                            pass # we mustn't send the w packet (thread exit) immediately, GDB will ask for it.
                first_stop = (e for e in events if lambda x: x['event'] == self.mod.EVENT_SUSPEND).next()
                if first_stop is None:
                    # what happened here? We got woken up, but no-one hit a breakpoint. So what now??
                    # self.send('N') # no running thread is left alive
                    self.log.error("No idea how to handle this wake-up. Everything from here on could be wrong!")
                    self.send('O%s' % hexlify("Got woken up and don't know why. Everything from here on could be wrong!"))
                    self.send('N')
                else:
                    self.send('T%.2xthread:%s;swbreak:;' % (GDB_SIGNAL_TRAP, hexlify(struct.pack('>I', first_stop['victim'])))) # signal that we reached a breakpoint

            dispatchers = {
                'q' : handle_general_query,
                '?' : handle_stop_reason,
                'g' : handle_get_regs,
                'm' : handle_mem_read,
                'M' : handle_mem_write,
                's' : handle_single_step,
                'Z' : handle_breakpoint_set,
                'z' : handle_breakpoint_remove,
                'c' : handle_continue,
                'H' : handle_set_thread,
                'T' : handle_thread_alive,
            }

            cmd, subcmd = pkt[0], pkt[1 :]
            if cmd == 'k':
                break

            if cmd not in dispatchers:
                self.log.warning('%r command not handled' % pkt)
                self.send('')
                continue

            dispatchers[cmd](subcmd)

        self.close()

    def receive(self):
        '''Receive a packet from a GDB client'''
        # XXX: handle the escaping stuff '}' & (n^0x20)
        csum = 0
        state = 'Finding SOP'
        packet = ''
        while True:
            c = self.netin.read(1)
            if c == '\x03':
                return 'Error: CTRL+C'

            if len(c) != 1:
                return 'Error: EOF'

            if state == 'Finding SOP':
                if c == '$':
                    state = 'Finding EOP'
            elif state == 'Finding EOP':
                if c == '#':
                    if csum != int(self.netin.read(2), 16):
                        raise Exception('invalid checksum')
                    self.last_pkt = packet
                    return 'Good'
                else:
                    packet += c
                    csum = (csum + ord(c)) & 0xff
            else:
                raise Exception('should not be here')

    def send(self, msg):
        '''Send a packet to the GDB client'''
        self.log.debug('send(%r)' % msg)
        self.send_raw('$%s#%.2x' % (msg, checksum(msg)))

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()


def main(program_args):

    logging.basicConfig(level = logging.WARN)
    for logger in 'gdbclienthandler runner main'.split(' '):
        logging.getLogger(logger).setLevel(level = logging.INFO)

    log = logging.getLogger('main')
    port = 31337
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))

    tgid = subprocess.Popen(program_args).pid

    log.info('listening on :%d' % port)
    sock.listen(1)
    conn, addr = sock.accept()
    log.info('connected')

    GDBClientHandler(conn, tgid).run()


if __name__ == '__main__':
    main(sys.argv[1:])
