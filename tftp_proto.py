import os
import struct
import random
import logging
from hardcoded_settings import FILE_BLOCK_SIZE, MAX_PACKET_SIZE


proto_logger = logging.getLogger('proto')


class PacketTypes(object):
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5
    INFO = 206
    INFO_ACK = 207


class Errors(object):
    NOT_DEFINED = (0, "Not defined, see error message (if any)")
    NOT_FOUND = (1, "File not found")
    ACCESS_VIOLATION = (2, "Access violation")
    DISK_FULL = (3, "Disk full or allocation exceeded")
    ILLEGAL_OPERATION = (4, "Illegal TFTP operation")
    UNKNOWN_PORT = (5, "Unknown transfer ID")
    FILE_EXISTS = (6, "File already exists")
    NO_SUCH_USER = (7, "No such user")
    MAX_RETRY_EXCEEDED = (100, "Max retry count exceeded")
    INTERNAL_ERROR = (101, "Server internal error. See server logs for details")


def net2int(data):
    assert len(data) == 2
    return struct.unpack("!H", data)[0]


def net2long(data):
    assert len(data) == 8
    return struct.unpack("!Q", data)[0]


def long2net(val):
    return struct.pack("!Q", val)


def parse_addrs(addrs_s):
    addrs = []
    if 0 != len(addrs_s):
        for addr_s in addrs_s.split(","):
            ip, port = addr_s.split(":")
            addrs.append((ip, int(port)))
    return addrs


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
        assert data[2:].count('\x00') == 2 and data[-1] == '\x00'
        fname, server_addrs_s, _ = data[2:].split("\x00")
        return opcode, (fname, parse_addrs(server_addrs_s))
    elif opcode == PacketTypes.INFO_ACK:
        fname, rest = data[2:].split("\x00", 1)
        if len(fname) > 0:
            size = net2long(rest[:8])

            blocks_in_file = (size + FILE_BLOCK_SIZE - 1) // FILE_BLOCK_SIZE

            eidx = (blocks_in_file + 7) // 8
            awail_bytes = rest[8:8 + eidx]
            rest = rest[8 + eidx:]
            awail_blocks = []

            for byte in map(ord, awail_bytes):
                awail_blocks.extend((byte & (0x80 >> idx)) != 0 for idx in range(8))

            awail_blocks = awail_blocks[:blocks_in_file]
        else:
            size = awail_blocks = None

        assert rest.count('\x00') == 1 and rest[-1] == '\x00'
        return opcode, (fname, size, awail_blocks, parse_addrs(rest[:-1]))
    raise AssertionError("Unknown opcode {}".format(opcode))


# INFO -> INFO;FILENAME\0
# INFO_R -> INFO_R;FILENAME\0;SIZE_2b;BLOCKS;OTHER_IPS\0


def addrs_to_str(addrs, max_sz):
    random.shuffle(addrs)
    res = "{}:{}".format(*addrs[0])
    for ip, port in addrs[1:]:
        addr_s = "{}:{}".format(ip, port)
        if len(res + addr_s) > max_sz:
            break
        res += ',' + addr_s
    return res


def make_tftp_packet(code, *params):
    res = struct.pack("!H", code)
    if code == PacketTypes.DATA:
        assert len(params) == 2
        assert isinstance(params[0], int)
        assert isinstance(params[1], str)
        assert len(params[1]) <= 512
        res += struct.pack("!H", params[0]) + params[1]
    elif code == PacketTypes.INFO_ACK:
        fname, size, awail_blocks, addrs = params

        if fname:
            res += fname + "\x00" + long2net(size)
            if len(awail_blocks) % 8 != 0:
                awail_blocks = awail_blocks + [False] * (8 - len(awail_blocks) % 8)

            for idx in range(len(awail_blocks) / 8):
                val = 0
                for block_ready in awail_blocks[idx * 8:(idx + 1) * 8]:
                    val = val * 2 + (1 if block_ready else 0)
                res += chr(val)
        else:
            res += "\x00"

        if addrs:
            res += addrs_to_str(addrs, MAX_PACKET_SIZE - len(res) - 2)
        res += "\x00"
    elif code == PacketTypes.INFO:
        fname, addrs = params
        res += fname + "\x00"
        if addrs:
            res += addrs_to_str(addrs, MAX_PACKET_SIZE - len(res) - 2)
        res += "\x00"
    else:
        for i in params:
            if isinstance(i, int):
                res += struct.pack("!H", i)
            else:
                assert isinstance(i, str)
                if code == PacketTypes.DATA:
                    res += i
                    assert len(params) == 2
                else:
                    res += i + '\x00'
    return res


def parse_initial_packet(packet):
    code, params = parse_packet(packet)
    if code in (PacketTypes.RRQ, PacketTypes.INFO, PacketTypes.ERROR):
        return code, params
    return PacketTypes.ERROR, Errors.ILLEGAL_OPERATION


def parse_and_sanitize_filepath(root, path):
    name_and_params = path.split(TFTPproto.offset_separator)

    if len(name_and_params) == 1:
        fname, boffset, eoffset = path, None, None
    else:
        assert len(name_and_params) == 3
        fname, boffset, eoffset = name_and_params
        boffset = int(boffset)
        eoffset = int(eoffset)

    assert os.path.sep not in fname
    fpath = os.path.join(root, fname)
    return fpath, boffset, eoffset


class TFTPproto(object):
    max_retry_count = 3
    transfer_block_size = 512
    offset_separator = "::"
    timeout = 1

    def __init__(self, fileobj, boffset, eoffset, result_cb=None, err_cb=None, data_cb=None):
        self.packet_pos = None
        self.retry_count = 0

        if fileobj is not None:
            self.boffset = 0 if boffset is None else boffset

            if eoffset is None:
                fileobj.seek(0, os.SEEK_END)
                self.eoffset = fileobj.tell()
            else:
                self.eoffset = eoffset

        self.last_packet = None
        self.fileobj = fileobj
        self.pos = 0
        self.result_cb = result_cb
        self.err_cb = err_cb
        self.data_cb = data_cb

    @classmethod
    def create_read_file(cls, filename, fileobj, boffset, eoffset, **callbacks):
        assert (boffset is None) == (eoffset is None)
        if boffset is not None:
            assert boffset < eoffset
            filename = cls.offset_separator.join((filename, str(boffset), str(eoffset)))
        self = cls(fileobj, boffset, eoffset, **callbacks)
        self.last_packet = make_tftp_packet(PacketTypes.RRQ, filename, 'octet')
        return self, self.on_file_data, self.last_packet

    @classmethod
    def create_get_info(cls, filename, servers, **callbacks):
        self = cls(None, None, None, **callbacks)
        self.last_packet = make_tftp_packet(PacketTypes.INFO, "" if filename is None else filename, servers)
        return self, self.on_info_recv, self.last_packet

    @classmethod
    def create_send_file(cls, fileobj, boffset, eoffset, **callbacks):
        assert (boffset is None) == (eoffset is None)
        if boffset is not None:
            assert boffset < eoffset
        self = cls(fileobj, boffset, eoffset, **callbacks)
        next_cb, data = self.send_next_block()
        return self, next_cb, data

    def on_info_recv(self, _, data):
        if data is None:
            self.close(True)
        else:
            if self.data_cb:
                self.data_cb()
            cmd, params = parse_packet(data)
            assert cmd == PacketTypes.INFO_ACK
            self.close(False, params)
        return None, None

    def close(self, err, data=None):
        err_cb = self.err_cb
        res_cb = self.result_cb

        # to prevent ec() from call itself via 'self.close'
        self.err_cb = self.result_cb = None

        if err and err_cb is not None:
            err_cb(data)
        elif not err and res_cb is not None:
            res_cb(data)

    def on_file_data(self, _, packet):
        if packet is None:
            # timeout
            if self.retry_count == self.max_retry_count:
                self.close(True, Errors.MAX_RETRY_EXCEEDED)
                return None, None

            self.retry_count += 1
            return self.on_file_data, self.last_packet

        if self.data_cb:
            self.data_cb()

        code, params = parse_packet(packet)

        if code == PacketTypes.DATA:
            self.retry_count = 0

            if self.pos == params[0]:
                return self.on_file_data, self.last_packet

            assert self.pos + 1 == params[0]
            self.pos = params[0]
            data = params[1]
            curr_offset = self.boffset + (self.pos - 1) * self.transfer_block_size

            self.fileobj.seek(curr_offset)
            self.fileobj.write(data)
            self.last_packet = make_tftp_packet(PacketTypes.ACK, self.pos)

            if (len(data) < self.transfer_block_size) or \
               (self.eoffset is not None and curr_offset + len(data) >= self.eoffset):
                self.close(False)
                return None, self.last_packet

            return self.on_file_data, self.last_packet
        elif code == PacketTypes.ERROR:
            self.close(True, params)
            return None, None

        self.close(True, Errors.ILLEGAL_OPERATION)
        return None, make_tftp_packet(PacketTypes.ERROR, *Errors.ILLEGAL_OPERATION)

    def send_next_block(self):
        self.pos += 1
        curr_offset = self.boffset + (self.pos - 1) * self.transfer_block_size

        if self.eoffset is not None:
            rsize = max(0, min(self.transfer_block_size, self.eoffset - curr_offset))
        else:
            rsize = self.transfer_block_size

        if 0 != rsize:
            self.fileobj.seek(curr_offset)
            data = self.fileobj.read(rsize)
        else:
            data = ""

        self.last_packet = make_tftp_packet(PacketTypes.DATA, self.pos, data)
        return self.on_data_ack, self.last_packet

    def on_data_ack(self, _, packet):
        if packet is None:
            # timeout
            if self.retry_count == self.max_retry_count:
                self.close(True, Errors.MAX_RETRY_EXCEEDED)
                return None, None

            self.retry_count += 1
            return self.on_data_ack, self.last_packet

        if self.data_cb:
            self.data_cb()

        code, params = parse_packet(packet)

        if code == PacketTypes.ACK:
            self.retry_count = 0
            if self.pos - 1 == params[0]:
                return self.on_data_ack, self.last_packet

            assert self.pos == params[0]
            return self.send_next_block()
        elif code == PacketTypes.ERROR:
            self.close(True, params)
            return None, None

        res = make_tftp_packet(PacketTypes.ERROR, *Errors.ILLEGAL_OPERATION)
        self.close(True, Errors.ILLEGAL_OPERATION)
        return None, res
