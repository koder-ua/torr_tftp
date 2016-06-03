from __future__ import print_function

import sys
import time
import heapq
import select
import socket
import random
import os.path
import logging
import argparse
import functools
import collections


def make_console_logger(name, level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


proto_logger = make_console_logger('proto')
main_logger = make_console_logger('main')
tor_logger = make_console_logger('tor')


class PacketTypes(object):
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5
    INFO = 206


class Errors(object):
    NOT_DEFINED = (0, "Not defined, see error message (if any)")
    NOT_FOUND = (1, "File not found")
    ACCESS_VIOLATION = (2, "Access violation")
    DISK_FULL = (3, "Disk full or allocation exceeded")
    ILLIGAL_OPERATION = (4, "Illegal TFTP operation")
    UNKNOWN_PORT = (5, "Unknown transfer ID")
    FILE_EXISTS = (6, "File already exists")
    NO_SUCH_USER = (7, "No such user")
    MAX_RETRY_EXCEEDED = (100, "Max retry count exceeded")


def net2int(data):
    assert len(data) == 2
    return ord(data[0]) * 256 + ord(data[1])


def int2net(val):
    assert val > 0 and val < 256 * 256
    return chr(val // 256) + chr(val % 256)


def parse_packet(data):
    opcode = net2int(data[:2])
    if opcode == PacketTypes.RRQ or opcode == PacketTypes.WRQ:
        name, mode, empty = data[2:].split("\x00")
        assert mode in ("netascii", "octet")
        assert empty == ''
        return opcode, (name, mode)
    elif opcode == PacketTypes.DATA:
        pos = net2int(data[2:4])
        file_data = data[4:]
        assert len(file_data) <= 512
        return opcode, (pos, file_data)
    elif opcode == PacketTypes.ACK:
        assert len(data) == 4
        return opcode, (net2int(data[2:]),)
    elif opcode == PacketTypes.ERROR:
        code = net2int(data[2:4])
        message = data[4:-2]
        assert data[-1] == '\x00'
        return opcode, (code, message)
    elif opcode == PacketTypes.INFO:
        return opcode, (data[2:].split("\x00")[:-1],)
    raise AssertionError("Unknown opcode {}".format(opcode))


def make_responce(code, *params):
    res = int2net(code)
    if code == PacketTypes.DATA:
        assert len(params) == 2
        assert isinstance(params[0], int)
        assert isinstance(params[1], str)
        assert len(params[1]) <= 512
        return res + int2net(params[0]) + params[1]

    for i in params:
        if isinstance(i, int):
            res += int2net(i)
        else:
            assert isinstance(i, str)
            if code == PacketTypes.DATA:
                res += i
                assert len(params) == 2
            res += i + '\x00'
    return res


def get_file_info(fname):
    return fname


def get_file_mm_read(fname, boffset=None, eoffset=None):
    pass


def get_file_mm_write(fname, boffset=None, eoffset=None):
    pass


def clear_tempo_mm(mm):
    pass


def save_tempo_mm(mm):
    pass


class TFTPproto(object):
    max_retry_count = 3
    transfer_block_size = 512
    offset_separator = "::"
    timeout = 1

    def __init__(self, fileobj, result_cb=None, err_callback=None):
        self.mm = None
        self.pos = None
        self.retry_count = None
        self.boffset = None
        self.eoffset = None
        self.last_packet = None
        self.result_cb = result_cb
        self.err_callback = err_callback
        self.write_file = False
        self.fileobj = fileobj

    def close(self, err, data=None):
        if err:
            if self.write_file:
                clear_tempo_mm(self.mm)
            if self.err_callback is not None:
                self.err_callback(data)
        else:
            if self.write_file:
                save_tempo_mm(self.mm)
            if self.result_cb is not None:
                self.result_cb(data)

    def init_read(self, rpath, boffset=None, eoffset=None, legacy_server=False):
        assert (boffset is None) ^ (eoffset is None)
        if boffset is not None and not legacy_server:
            rpath = self.offset_separator.join(
                [rpath, str(boffset), str(eoffset)])

        self.boffset = boffset
        self.eoffset = eoffset
        self.pos = 0
        self.mm = get_file_mm_read(fname)
        self.last_packet = make_responce(PacketTypes.RRQ, rpath, 'octet')
        return self.recv_file, self.last_packet

    def init_write(self, rpath, lpath, boffset=None, eoffset=None):
        self.pos = 0
        raise NotImplementedError()

    def get_info(self, fname):
        return self.on_done, make_responce(PacketTypes.INFO, fname)

    def parse_filepath_and_sanitize(self, path, write=False):
        name_and_params = path.split(self.offset_separator)

        if len(name_and_params) == 1:
            fname, boffset, eoffset = name_and_params[0], None, None
        else:
            assert len(name_and_params) == 3
            fname, boffset, eoffset = name_and_params
            boffset = int(boffset)
            eoffset = int(eoffset)

        assert '/' not in fname
        fpath = os.path.join(self.root, path)

        return fpath, boffset, eoffset

    def init_packet(self, packet):
        code, params = parse_packet(packet)

        if code == PacketTypes.RRQ:
            fname, mode = params
            fname, self.boffset, self.eoffset = self.parse_and_sanitize(fname)
            self.mm = get_file_mm_read(fname)

            if self.boffset is None:
                self.boffset = 0
                self.eoffset = self.mm.size()

            assert self.boffset < self.eoffset <= self.mm.size()

            self.pos = 1
            self.retry_count = 0
            return self.send_next_block()

        elif code == PacketTypes.WRQ:
            fname, mode = params
            fname, boffset, eoffset = self.parse_and_sanitize(fname)

            assert boffset is None
            assert eoffset is None

            self.mm = get_file_mm_write(fname)
            self.write = True

            self.retry_count = 0
            self.pos = 1
            self.last_packet = make_responce(PacketTypes.ACK, 0)
            return self.recv_file, self.last_packet
        elif code == PacketTypes.ERROR:
            return self.close(True, params)
        elif code == PacketTypes.INFO:
            if len(params) == 0:
                res = make_responce(PacketTypes.INFO)
                self.close(False)
                return None, res
            elif len(params) == 1:
                res = make_responce(PacketTypes.INFO, get_file_info(params[0]))
                self.close(False)
                return None, res

        res = make_responce(PacketTypes.ERROR, *Errors.ILLIGAL_OPERATION)
        self.close(True, Errors.ILLIGAL_OPERATION)
        return None, res

    def send_next_block(self):
        curr_offset = self.boffset * (self.pos - 1) * self.transfer_block_size

        if self.end_offset is not None:
            rsize = min(self.transfer_block_size, self.end_offset - curr_offset)
        else:
            rsize = self.transfer_block_size

        self.last_packet = make_responce(PacketTypes.DATA, self.pos,
                                         self.mm[curr_offset:curr_offset + rsize])
        return self.on_send_ack, self.last_packet

    def on_send_ack(self, packet):
        if packet is None:
            # timeout
            if self.retry_count == self.max_retry_count:
                self.close(True, self.MAX_RETRY_EXCEEDED)
                return None, None

            self.retry_count += 1
            return self.on_send_ack, self.last_packet

        code, params = parse_packet(packet)

        if code == PacketTypes.ACK:
            self.retry_count = 0
            if self.pos - 1 == params[0]:
                return self.send_file, self.last_packet

            assert self.pos == params[0]
            self.pos += 1
            return self.send_next_block()
        elif code == PacketTypes.ERROR:
            self.close(True, params)
            return None, None

        res = make_responce(PacketTypes.ERROR, *Errors.ILLIGAL_OPERATION)
        self.close(True, Errors.ILLIGAL_OPERATION)
        return None, res

    def recv_file(self, packet):
        if packet is None:
            # timeout
            if self.retry_count == self.max_retry_count:
                self.close(True, self.MAX_RETRY_EXCEEDED)
                return None, None

            self.retry_count += 1
            return self.recv_file, self.last_packet

        code, params = parse_packet(packet)

        if code == PacketTypes.DATA:
            self.retry_count = 0
            if self.pos == params[0]:
                return self.recv_file, self.last_packet

            assert self.pos + 1 == params[0]
            self.pos = params[0]
            data = params[1]
            curr_offset = self.boffset * (self.pos - 1) * self.transfer_block_size
            self.mm[curr_offset:curr_offset + len(data)] = data
            self.last_packet = make_responce(PacketTypes.ACK, self.pos)

            if (len(data) < self.transfer_block_size) or \
               (self.eoffset is not None and curr_offset + len(data) >= self.eoffset):
                self.close(False)
                return None, self.last_packet

            return self.recv_file, self.last_packet
        elif code == PacketTypes.ERROR:
            self.close(True, params)
            return None, None

        res = make_responce(PacketTypes.ERROR, *Errors.ILLIGAL_OPERATION)
        self.close(True, Errors.ILLIGAL_OPERATION)
        return None, res


class DloadBlock(object):
    def __init__(self, boffset, eoffset):
        self.done = False
        self.active_server = None
        self.boffset = boffset
        self.eoffset = eoffset
        self.servers = set()


class Server(object):
    def __init__(self, addr, legacy=False):
        self.addr = addr
        self.legacy = legacy
        self.last_ping_time = 0
        self.files_info = {}
        self.dload_count = 0
        self.upload_count = 0


class FileInfo(object):
    def __init__(self, size, awailable_blocks):
        self.size = size
        self.awailable_blocks = awailable_blocks


class DLoad(object):
    NEW = 0
    IN_PROGRESS = 1
    DONE = 2

    def __init__(self, fname):
        self.status = self.NEW
        self.blocks = []
        self.blocks_ready_to_load = []
        # self.legacy_servers_q = None

        self.data_lenght = None
        self.fname = None
        self.fd = None
        self.mmap = None


class CB(object):
    def __init__(self, func, evt, fileobj, timeout_at):
        self.func = func
        self.evt = evt
        self.fileobj = fileobj
        self.timeout_at = timeout_at
        self.fd = fileobj.fileno() if fileobj is not None else None


class Reactor(object):
    def_recv_size = 1024

    def __init__(self):
        self.selector = select.epoll()

        self.fd2cb = {}
        self.callbacks_heap = []

        self.selector.register(self.master_sock, select.POLLIN)
        self.selector.register(self.control_sock, select.POLLIN)

    def register(self, fileobj, evt, cb_func, timeout):
        if timeout != -1:
            timeout_at = int(timeout + time.time() * self.SECOND)
        else:
            timeout_at = None

        cb = self.fd2cb.get(fileobj.fileno())
        if not cb:
            self.selector.register(fileobj, evt)
            cb = CB(cb_func, evt, fileobj, timeout_at)
            self.fd2cb[cb] = fileobj
        else:
            assert cb.fileobj is fileobj
            assert cb.evt == evt
            cb.func = cb_func
            cb.timeout_at = timeout_at

        if timeout_at is not None:
            heapq.heappush(self.callbacks, (timeout_at, cb))

    def unregister(self, fileobj):
        self.selector.unregister(fileobj)
        cb = self.fd2cb[fileobj.fileno()]
        del self.fd2cb[fileobj.fileno()]
        assert cb.tout_time is not None
        cb.evt = cb.func = cb.fd = cb.fileobj = None
        cb.timeout_at = 0

    def call_later(self, tout, func):
        call_at = int(tout + time.time() * self.SECOND)
        cb = CB(func, None)
        heapq.heappush(self.callbacks, (call_at, cb))

    def serve_forever(self):
        while True:
            ctime = time.time()
            while ctime >= self.callbacks[0][0]:
                _, cb = heapq.heappop(self.callbacks)
                if cb.func is None:
                    continue
                if cb.timeout_at > ctime:
                    heapq.heapush(self.callbacks, (cb.timeout_at, cb))
                else:
                    if cb.fileobj is None:
                        cb.func()
                    else:
                        cb.func(None, None)
                    ctime = time.time()

            wait_tout = self.callbacks[0][0] - time.time()
            for fd, _ in self.selector.poll(wait_tout):
                cb = self.fd2cb[fd]
                data, remote_addr = cb.fileobj.recvfrom(self.def_recv_size)
                cb.func(remote_addr, data)


class TFTPServer(object):
    file_block_size = 16 * 2 ** 20
    max_file_size = 1024 * file_block_size

    max_dload_count = 16
    max_updload_count = 16

    max_conn_per_server = 4
    SECOND = 1000 * 1000

    def __init__(self, root, bind_host, port=33348,
                 control_sock_path="/tmp/tftp_control_sock", poll_tout=1000):
        self.master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.master_sock.bind((bind_host, port))
        self.bind_host = bind_host
        self.root = root

        self.dload_count = 0
        self.upload_count = 0

        self.servers = []
        # self.legacy_servers = []

        if os.path.exists(control_sock_path):
            os.unlink(control_sock_path)

        # blacklist of broken/slow servers. heapq with remove timeout
        self.servers_blist_heap = []
        self.servers_blist = set()

        self.control_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.control_sock.bind(control_sock_path)

        self.reactor = Reactor()
        self.reactor.register(self.control_sock, select.POLLIN,
                              self.on_control_msg, None)
        self.reactor.register(self.master_sock, select.POLLIN,
                              self.on_master_sock, None)

    def update_dload(self, dload):
        if dload.status == DLoad.DONE:
            return

        # if dload.status == DLoad.NEW:
        #     # if no NEW servers found
        #     if dload.ready_to_load == []:
        #         # try to start entire load from legacy server
        #         if dload.legacy_servers_q is None:
        #             dload.legacy_servers_q = self.legacy_servers
        #         random.shuffle(dload.legacy_servers_q)
        #         srv = dload.legacy_servers_q.pop()
        #
        #         # start entire dload. will then
        #         results_cb = functools.partial(self.on_dload_complete,
        #                                        dload, awail_block)
        #         err_cb = functools.partial(self.on_block_dload_error,
        #                                    dload, awail_block)
        #         proto = self.add_proto(results_cb, err_cb)
        #         self.new_proto_data(proto, proto.init_read, server.addr,
        #                             rpath=dload.fname,
        #                             boffset=awail_block,
        #                             eoffset=awail_block + 1)
        #
        #         dload.status = dload.IN_PROGRESS
        #         dload.dload_count += 1

        if not dload.ready_to_load:
            for block in dload.blocks:
                if not block.done:
                    break
        else:
            # dload complete
            self.on_dload_complete(dload)

        free_slots = self.max_dload_count - self.dload_count
        if free_slots <= 0:
            return

        # TODO(koder): randomize this
        will_start = dload.ready_to_load[:free_slots]
        dload.ready_to_load = dload.ready_to_load[free_slots:]

        for awail_block in will_start:
            assert awail_block.server is None
            assert awail_block.servers
            random.shuffle(awail_block.servers)

            while len(awail_block.servers) > 0:
                server = awail_block.servers[-1]
                if server not in self.servers_blist:
                    break
                awail_block.servers.pop()
            else:
                # will wait for new update
                return

            results_cb = functools.partial(self.on_block_dload_complete,
                                           dload, awail_block)
            err_cb = functools.partial(self.on_block_dload_error,
                                       dload, awail_block)
            proto = self.add_proto(results_cb, err_cb)
            self.new_proto_data(proto, proto.init_read, server.addr,
                                rpath=dload.fname,
                                boffset=awail_block,
                                eoffset=awail_block + 1)

            dload.status = dload.IN_PROGRESS
            dload.dload_count += 1

    def start_dload(self, params):
        if " " not in params:
            main_logger.error("Wrong download params: %r", params)
            return

        mode, path = params.split(" ", 1)
        dload = DLoad(path, mode)
        self.update_servers_status(dload)
        self.reactor.call_later(self.SECOND, functools.partial(self.update_dload, dload))
        self.reactor.call_later(self.MINUTE, functools.partial(self.on_dload_failed, dload))
        self.downloads.append(dload)

    def update_servers_status(self, dload):
        if dload.status == DLoad.DONE:
            return

        for server in self.servers:
            ready_cb = functools.partial(self.on_get_file_info, dload, server.addr)
            err_cb = functools.partial(self.on_get_file_info_failed, dload, server.addr)
            proto = self.add_proto(ready_cb, err_cb)
            self.new_proto_data(proto, proto.get_info, server.addr, dload.fname)

        self.reactor.call_later(10 * self.SECOND, functools.partial(self.update_servers_status, dload))
        self.reactor.call_later(self.SECOND, functools.partial(self.update_dload, dload))

    def add_proto(self, result_cb=None, error_cb=None):
        fileobj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fileobj.bind((self.bind_host, 0))
        return TFTPproto(fileobj, result_cb, error_cb)

    def on_new_connection(self, data, addr):
        proto = self.add_proto()
        self.new_proto_data(proto, proto.init_packet, addr, data)
        return self.on_new_connection, None

    def on_control_cmd(self, data, addr):
        cmd, params = data.split(" ", 1)
        main_logger.info("New cmd: %r %r", cmd, params)
        if cmd == 'servers':
            for addr_s in params.split(" "):
                host, port = addr_s.split(":")
        elif cmd == "dload":
            self.start_dload(params)
        else:
            main_logger.error("Unknown cmd %r", cmd)

    def new_proto_data(self, proto, callback, remote_addr, *args, **kwargs):
        try:
            next_cb, msg = callback(*args, **kwargs)
        except Exception:
            main_logger.exception("During call callback")
            next_cb = msg = None
            proto.close(True, None)

        if msg is not None:
            proto.fileobj.sendto(msg, remote_addr)

        if next_cb is None:
            self.reactor.unregister(proto.fileobj)
            proto.fileobj.close()
        else:
            callback = functools.partial(self.new_proto_data, proto, next_cb)
            self.reactor.register(proto.fileobj, select.POLLIN, callback, proto.timeout)

    def on_block_dload_complete(self, dload, block_num):
        dload.dload_count += 1
        block = dload.blocks[block_num]
        block.done = True
        block.active_server = None
        block.servers.clear()
        self.update_dload(dload)
        raise NotImplemented()

    def on_block_dload_failed(self, dload, block_num):
        block = dload.blocks[block_num]
        # check server error count and error type
        block.servers.remove(block.active_server)
        block.active_server = None
        self.dload_me.add(block)
        self.update_dload(dload)
        raise NotImplemented()

    def on_dload_complete(self, dload):
        raise NotImplemented()

    def on_dload_failed(self, dload):
        if dload.status == DLoad.NEW:
            return
        raise NotImplemented()

    def on_get_file_info_failed(self, dload, server_addr, error):
        # check server error count
        raise NotImplemented()

    def on_get_file_info(self, dload, server, info):
        dload.servers[server.addr] = (server, info)

        if dload.size is None:
            dload.size = info.size
            bcount = info.size // self.file_block_size
            if info.size % self.file_block_size != 0:
                bcount += 1

            dload.blocks = []
            for i in range(bcount):
                eoffset = min(info.size, (i + 1) * self.file_block_size)
                dload.blocks.append(DloadBlock(i * self.file_block_size, eoffset))

            self.dload_me = set(range(bcount))

        for awail_block in info.awailable_blocks:
            dload.blocks[awail_block].servers.add(server.addr)
        raise NotImplemented()

    def serve_forever(self):
        self.proto.serve_forever()


def main(argv):
    control_sock_default_path = "/tmp/tftp_control_sock"

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='commands')

    cmd_parser = subparsers.add_parser('cmd', help='send cmd to server')
    cmd_parser.set_defaults(action='cmd')
    cmd_parser.add_argument('-f', '--control-file', default=control_sock_default_path)
    cmd_parser.add_argument("command", nargs='+')

    srv_parser = subparsers.add_parser('serve', help='start serving')
    srv_parser.set_defaults(action='serve')
    srv_parser.add_argument('port', type=int)
    srv_parser.add_argument('folder')
    srv_parser.add_argument('--ip', '-i', default='0.0.0.0')
    srv_parser.add_argument('-f', '--control-file', default=control_sock_default_path)

    opts = parser.parse_args(argv[1:])

    if opts.action == 'serve':
        ml = TFTPServer(opts.folder, bind_host=opts.ip, port=opts.port,
                        control_sock_path=opts.control_file)
        return ml.serve_forever()
    elif opts.action == 'cmd':
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(" ".join(opts.command), opts.control_file)
    else:
        assert False, "??????"


if __name__ == "__main__":
    exit(main(sys.argv))
