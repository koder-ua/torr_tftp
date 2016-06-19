"""
TFTP main module
"""

from __future__ import print_function

import os
import sys
import time
import mmap
import select
import socket
import random
import logging
import argparse
import warnings
import functools


def make_console_logger(name, level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    console_h = logging.StreamHandler()
    console_h.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)10s - %(levelname)6s - %(message)s')
    console_h.setFormatter(formatter)
    logger.addHandler(console_h)
    return logger


make_console_logger('proto')
main_logger = make_console_logger('main')
make_console_logger('reactor')


# have to import all local modules after setting up loggers
from tftp_proto import (TFTPproto,
                        Errors,
                        PacketTypes,
                        parse_initial_packet,
                        make_tftp_packet,
                        parse_packet,
                        parse_and_sanitize_filepath)
from reactor import Reactor
from hardcoded_settings import FILE_BLOCK_SIZE, MAX_FILE_SIZE, MAX_PACKET_SIZE


class DloadBlock(object):
    def __init__(self, boffset, eoffset):
        self.done = False
        self.active_server = None
        self.boffset = boffset
        self.eoffset = eoffset
        self.servers = set()
        self.idx = self.boffset // FILE_BLOCK_SIZE


class Server(object):
    ACTIVE = 0
    OFFLINE = 1
    ERROR = 2

    def __init__(self, addr):
        self.addr = addr
        self.errors_in_row = 0
        self.status = self.ACTIVE
        self.last_ping_at = None
        self.addr_s = "{}:{}".format(*self.addr)

    def on_data(self):
        self.errors_in_row = 0
        self.last_ping_at = time.time()


class FileInfo(object):
    def __init__(self):
        self.size = None
        self.ready_blocks = []
        self.fd = None
        self.mmap = None

    def get_fileobj(self):
        if self.mmap is None:
            return self.fd
        return self.mmap

    def close(self):
        self.mmap.close()
        self.fd.close()
        self.fd = self.mmap = None

    @classmethod
    def open(cls, fname):
        self = cls()
        self.fd = open(fname, 'r+b')
        self.fd.seek(0, os.SEEK_END)
        self.size = self.fd.tell()
        assert self.size <= MAX_FILE_SIZE
        bsz = (self.size + FILE_BLOCK_SIZE - 1) // FILE_BLOCK_SIZE
        self.ready_blocks = [True] * bsz
        self.mmap = mmap.mmap(self.fd.fileno(), 0, prot=mmap.PROT_WRITE | mmap.PROT_READ)
        return self

    @classmethod
    def create(cls, fname, size):
        assert size <= MAX_FILE_SIZE

        with open(fname, "wb") as fd:
            fd.seek(size - 1)
            fd.write("\x00")

        self = cls.open(fname)
        self.ready_blocks = [False] * len(self.ready_blocks)
        return self


class DLoad(object):
    NEW = 0
    IN_PROGRESS = 1
    DONE = 2
    FAILED = 3

    def __init__(self, file_info, requested_file_name, target_file_name, tmp_file_name):
        self.status = self.NEW
        self.blocks = []
        self.blocks_ready_to_load = set()
        self.servers_with_complete_file = set()

        # set only when get file info
        self.file_info = file_info
        self.tmp_file_name = tmp_file_name
        self.target_file_name = target_file_name
        self.requested_file_name = requested_file_name

    def __str__(self):
        return "{0.__class__.__name__}({0.requested_file_name!r})".format(self)

    def __repr__(self):
        return str(self)


def get_my_ip():
    # TODO(koder): need other way to get an ip
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.connect(("gmail.com", 80))
    return conn.getsockname()[0]


class TFTPServer(object):
    max_dload_count = 16
    max_updload_count = 16

    max_conn_per_server = 4
    max_server_tout = 120
    ping_timeout = 30

    illegal_op_pkt = make_tftp_packet(PacketTypes.ERROR, *Errors.ILLEGAL_OPERATION)
    internal_err_pkt = make_tftp_packet(PacketTypes.ERROR, *Errors.INTERNAL_ERROR)

    def __init__(self, root, bind_host, port=33348, control_sock_path="/tmp/tftp_control_sock"):
        self.master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.master_sock.bind((bind_host, port))
        self.bind_addr = (bind_host, port)
        self.control_sock_path = control_sock_path
        self.root = root

        bind_host_ip = socket.gethostbyname(bind_host)
        if bind_host_ip == '0.0.0.0' or bind_host_ip.startswith("127."):
            self.my_addr = (get_my_ip(), port)
        else:
            self.my_addr = (bind_host_ip, port)

        self.dload_count = 0
        self.upload_count = 0
        self.downloads = []

        self.files = {}  # name => FileInfo
        self.servers = {}  # addr => Server
        self.server_ping_queue = set()

        if os.path.exists(control_sock_path):
            os.unlink(control_sock_path)

        self.control_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.control_sock.bind(control_sock_path)

        self.reactor = Reactor()
        self.reactor.register(self.control_sock, select.POLLIN,
                              self.on_control_cmd, None)
        self.reactor.register(self.master_sock, select.POLLIN,
                              self.on_new_connection, None)
        self.reactor.call_later(60, self.check_servers)
        self.reactor.call_later(60, self.process_ping_queue)

    def close(self):
        self.reactor.close()

        control_and_master_fds = (self.control_sock.fileno(), self.master_sock.fileno())
        self.control_sock.close()
        self.master_sock.close()
        os.unlink(self.control_sock_path)

        for fd in self.reactor.fd2cb:
            if fd not in control_and_master_fds:
                os.close(fd)

    def on_new_connection(self, addr, data):
        code, params = parse_initial_packet(data)
        if code == PacketTypes.RRQ:
            main_logger.debug("RRQ request: %r", params)

            server = self.servers.get(addr)
            data_cb = None if server is None else server.on_data

            try:
                conn = self.open_sock()
            except Exception:
                main_logger.exception("Can't open new socket")
                return self.on_new_connection, None

            try:
                assert len(params) == 2
                assert params[1] == 'octet'
                path, boff, eoff = parse_and_sanitize_filepath(self.root, params[0])
                if path not in self.files:
                    finfo = FileInfo.open(path)
                else:
                    finfo = self.files[path]

                _, callback, data = TFTPproto.create_send_file(finfo.get_fileobj(), boff, eoff,
                                                               data_cb=data_cb)
                conn.sendto(data, addr)
                self.files[path] = finfo
            except AssertionError:
                main_logger.exception("Broken packet %r", data)
                conn.sendto(self.illegal_op_pkt, addr)
                conn.close()
            except Exception:
                main_logger.exception("During processing %r", data)
                conn.sendto(self.internal_err_pkt, addr)
                conn.close()
            else:
                self.reactor.register(conn, select.POLLIN, callback, TFTPproto.timeout)
        elif code == PacketTypes.INFO:
            main_logger.debug("INFO request: %r", params)
            try:
                assert len(params) == 2
                fname, server_addrs = params
                self.add_servers(server_addrs)
                info = self.get_info(fname if fname != "" else None)
                packet = make_tftp_packet(PacketTypes.INFO_ACK, params[0], *info)
                main_logger.debug("%r <= %r", addr, packet)
                self.master_sock.sendto(packet, addr)
            except AssertionError:
                main_logger.error("Broken packet %r", data)
                self.master_sock.sendto(self.illegal_op_pkt, addr)
            except Exception:
                main_logger.exception("During processing %r", data)
                self.master_sock.sendto(self.internal_err_pkt, addr)
        elif code == PacketTypes.ERROR:
            main_logger.warning("Unexpected ERROR request: %r", params)
        else:
            main_logger.warning("Unexpected request: %r %r", code, params)
            self.master_sock.sendto(make_tftp_packet(*Errors.ILLEGAL_OPERATION), addr)
        return self.on_new_connection, None

    def add_servers(self, servers):
        for addr in servers:
            if addr not in self.servers and addr != self.my_addr:
                srv = Server(addr)
                self.enqueue_ping_server(srv)
                self.servers[addr] = srv

    def on_control_cmd(self, _, data):
        cmd, params = data.split(" ", 1)
        main_logger.info("New cmd: %r %r", cmd, params)
        if cmd == 'servers':
            srv_addrs = []
            for srv_addr_s in params.split(" "):
                ip, port_s = srv_addr_s.split(":")
                srv_addrs.append((ip, int(port_s)))
            self.add_servers(srv_addrs)
        elif cmd == "dload":
            self.start_dload(params)
        else:
            main_logger.error("Unknown cmd %r", cmd)
        return self.on_control_cmd, None

    def get_info(self, fname):
        if fname is not None:
            path, _, _ = parse_and_sanitize_filepath(self.root, fname)
            if path in self.files:
                finfo = self.files[path]
                size = finfo.size
                awail_blocks = finfo.ready_blocks[:]
            elif os.path.isfile(path):
                finfo = FileInfo.open(path)
                self.files[path] = finfo
                size = finfo.size
                awail_blocks = finfo.ready_blocks[:]
            else:
                size = 0
                awail_blocks = []
        else:
            size = awail_blocks = None

        return size, awail_blocks, list(self.servers.keys()) + [self.my_addr]

    def check_servers(self):
        # ctime = time.time()

        # for server in self.servers.values():
        #     if server.last_ping_at is None:
        #         self.ping_server(server)

            # if ctime - server.last_ping_at > self.max_server_tout:
            #     server.status = server.OFFLINE
            # else:
            # if ctime - server.last_ping_at > self.max_server_tout and server.status == server.OFFLINE:
            #     server.status = server.ACTIVE
            # if ctime - server.last_ping_at > self.ping_timeout:
            #     self.ping_server(server)

        self.reactor.call_later(60, self.check_servers)

    def on_get_file_info_failed(self, dload, server, error):
        str(self)
        str(dload)
        str(error)
        server.errors_in_row += 1

    def on_get_file_info_replay(self, dload, server, info):
        main_logger.debug("Got responce for %r from server %r - %r", dload, server.addr_s, info)
        fname, size, awail_blocks, new_server_addrs = info
        self.add_servers(new_server_addrs)

        if fname == "":
            return

        if dload.status == dload.NEW:
            dload.file_info = FileInfo.create(dload.tmp_file_name, size)
            self.files[dload.target_file_name] = dload.file_info

        if all(awail_blocks):
            dload.servers_with_complete_file.add(server)

        dload.blocks = []
        for pos, is_awail in enumerate(awail_blocks):
            if dload.status == dload.NEW:
                eoffset = min(size, (pos + 1) * FILE_BLOCK_SIZE)
                dload.blocks.append(DloadBlock(pos * FILE_BLOCK_SIZE, eoffset))

            if is_awail:
                block = dload.blocks[pos]
                block.servers.add(server)
                dload.blocks_ready_to_load.add(block)

        dload.status = dload.IN_PROGRESS
        self.update_dload(dload)

    def update_dload(self, dload):
        if dload.status in (DLoad.DONE, DLoad.NEW):
            return

        if not dload.blocks_ready_to_load:
            for block in dload.blocks:
                if not block.done:
                    return
            # dload complete
            self.on_dload_complete(dload)
            return

        free_slots = self.max_dload_count - self.dload_count
        if free_slots <= 0:
            return

        num_blocks = min(free_slots, len(dload.blocks_ready_to_load))

        # TODO(koder): randomize this
        for _ in range(num_blocks):
            awail_block = dload.blocks_ready_to_load.pop()
            assert awail_block.active_server is None
            assert awail_block.servers
            random.shuffle(awail_block.servers)

            while awail_block.servers:
                server = awail_block.servers.pop()
                if server.status == server.ACTIVE:
                    break
            else:
                continue

            results_cb = functools.partial(self.on_block_dload_complete, dload, awail_block)
            err_cb = functools.partial(self.on_block_dload_failed, dload, awail_block)

            conn = self.open_sock()
            _, callback, data = TFTPproto.create_read_file(dload.requested_file_name,
                                                           dload.file_info.get_fileobj(),
                                                           awail_block.boffset,
                                                           awail_block.eoffset,
                                                           result_cb=results_cb,
                                                           err_cb=err_cb,
                                                           data_cb=server.on_data)
            conn.sendto(data, server.addr)
            self.reactor.register(conn, select.POLLIN, callback, TFTPproto.timeout)
            self.dload_count += 1
            awail_block.active_server = server

    def start_dload(self, params):
        if " " not in params:
            main_logger.error("Wrong download params: %r", params)
            return

        mode, path = params.split(" ", 1)
        main_logger.info("Start downloading %s mode=%s", path, mode)

        if os.path.sep in path:
            main_logger.error("Wrong file path %r", path)
            return

        final_dst_path = os.path.join(self.root, path)
        if path in self.files or os.path.isfile(final_dst_path):
            main_logger.error("File %r already exists or in progress", path)
            return

        assert path not in self.files
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tmpname = os.tempnam(self.root)

        dload = DLoad(None, path, final_dst_path, tmpname)
        self.downloads.append(dload)

        self.update_download_servers_info(dload)
        self.reactor.call_later(60, functools.partial(self.on_dload_failed_if_not_starts, dload))

    def on_server_ping_replay(self, server, info):
        if server.addr not in self.servers:
            self.servers[server.addr] = server

        fname, _, _, new_server_addrs = info
        assert fname == ""
        self.add_servers(new_server_addrs)

    def process_ping_queue(self):
        self.reactor.call_later(60, self.process_ping_queue)

    def enqueue_ping_server(self, server):
        self.server_ping_queue.add(server)

    def ping_server(self, server):
        ready_cb = functools.partial(self.on_server_ping_replay, server)
        conn = self.open_sock()
        _, callback, data = TFTPproto.create_get_info(None,
                                                      list(self.servers.keys()),
                                                      result_cb=ready_cb,
                                                      data_cb=server.on_data)
        conn.sendto(data, server.addr)
        self.reactor.register(conn, select.POLLIN, callback, TFTPproto.timeout)

    def update_download_servers_info(self, dload):
        if dload.status in (dload.DONE, dload.FAILED):
            return

        main_logger.debug("Updating servers stats for download %r", dload)
        for server in self.servers.values():
            if server in dload.servers_with_complete_file or server.status != server.ACTIVE:
                continue

            ready_cb = functools.partial(self.on_get_file_info_replay, dload, server)
            err_cb = functools.partial(self.on_get_file_info_failed, dload, server)

            conn = self.open_sock()
            _, callback, data = TFTPproto.create_get_info(dload.requested_file_name,
                                                          list(self.servers.keys()) + [self.my_addr],
                                                          result_cb=ready_cb,
                                                          err_cb=err_cb,
                                                          data_cb=server.on_data)
            conn.sendto(data, server.addr)
            self.reactor.register(conn, select.POLLIN, callback, TFTPproto.timeout)

        self.reactor.call_later(10, functools.partial(self.update_download_servers_info, dload))
        self.reactor.call_later(1, functools.partial(self.update_dload, dload))

    def open_sock(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.bind((self.bind_addr[0], 0))
        return conn

    def on_block_dload_complete(self, dload, block, _):
        self.dload_count -= 1
        dload.file_info.ready_blocks[block.idx] = True
        block.done = True
        block.active_server = None
        block.servers.clear()
        self.update_dload(dload)

    def on_block_dload_failed(self, dload, block, _):
        self.dload_count -= 1
        block.active_server.errors_in_row += 1
        block.active_server = None
        if block.servers:
            dload.blocks_ready_to_load.add(block)
        self.update_dload(dload)

    def on_dload_complete(self, dload):
        dload.status = dload.DONE
        assert dload.blocks_ready_to_load == set(), "{!r} != set()".format(dload.blocks_ready_to_load)
        assert all(dload.file_info.ready_blocks), ",".join(map(str, dload.file_info.ready_blocks))
        os.rename(dload.tmp_file_name, dload.target_file_name)
        dload.tmp_file_name = None
        dload.file_info.close()
        del self.files[dload.target_file_name]
        main_logger.info("Download of file %r complete", dload.requested_file_name)
        self.downloads.remove(dload)

    def on_dload_failed_if_not_starts(self, dload):
        if dload.status == DLoad.NEW:
            main_logger.error("Download of file %r failed", dload.requested_file_name)
            dload.status = dload.FAILED
            self.downloads.remove(dload)
            return

    def serve_forever(self):
        main_logger.info("Server start on %r, using %r folder, %r control sock",
                         ":".join(map(str, self.bind_addr)), self.root, self.control_sock_path)

        self.reactor.serve_forever()


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

    cli_parser = subparsers.add_parser('cli', help='send cmd from cli over proto')
    cli_parser.set_defaults(action='cli')
    cli_parser.add_argument('-t', '--timeout', type=int, default=1)
    cli_parser.add_argument('ip')
    cli_parser.add_argument('port', type=int)
    cli_parser.add_argument('cmd', choices=['info'])
    cli_parser.add_argument('params', nargs='*', default=[])

    opts = parser.parse_args(argv[1:])

    if opts.action == 'serve':
        server = TFTPServer(opts.folder, bind_host=opts.ip, port=opts.port,
                            control_sock_path=opts.control_file)
        try:
            return server.serve_forever()
        except KeyboardInterrupt:
            main_logger.info("Got keyaboard interrupt, exiting. Bye!")
        finally:
            server.close()

    elif opts.action == 'cmd':
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(" ".join(opts.command), opts.control_file)
    elif opts.action == 'cli':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cmd_id = {
            'info': PacketTypes.INFO
        }

        if len(opts.params) == 0:
            opts.params = [""]

        pkt = make_tftp_packet(cmd_id[opts.cmd], *opts.params)
        sock.sendto(pkt, (opts.ip, opts.port))
        read, _, _ = select.select([sock], [], [], opts.timeout)

        if len(read) == 0:
            print("Timeout!")
        else:
            data = sock.recv(MAX_PACKET_SIZE)
            print(parse_packet(data))
    else:
        assert False, "??????"


if __name__ == "__main__":
    exit(main(sys.argv))
