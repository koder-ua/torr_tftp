package main

import ("net"
        "bytes"
        "errors"
        "encoding/binary")

const (
    INFO = iota
    INFO_RESP = iota
    READ = iota
    DATA = iota
    DATA_ACK = iota
    ERROR = iota
    PING = iota
)

const (
    ERR_OK = iota
    ERR_UNKNOWN_CMD = iota
    ERR_WRONG_CMD = iota
    ERR_BROKEN_PACKET = iota
)

type InfoMessage struct {
    addr *net.UDPAddr
    fname string
    servers []net.UDPAddr
}

type InfoMessageResp struct {
    fname string
    size int64
    blocks_awail []bool
    servers []net.UDPAddr
}

type ReadMessage struct {
    fname string
    boffset uint64
    effset uint64
}

type DataMessage struct {
    index int
    data []byte
}

type DataAckMessage struct {
    max_received_idx int
    missing_idx []int
}

type InfoRMessage struct {
    addr *net.UDPAddr
    msg *InfoMessage
}

type Server struct {
    addr *net.UDPAddr
}

func parseInfoMessage(data []byte, addr *net.UDPAddr) (*InfoMessage, int, error) {
    fname_ends := bytes.IndexByte(data, byte(0))

    if fname_ends == -1 {
        return nil, ERR_BROKEN_PACKET, errors.New("Broken INFO message - no 0 char after filename")
    }

    fname := string(data[:fname_ends])
    data = data[fname_ends + 1:]
    if 0 != len(data) % 6 {
        return nil, ERR_BROKEN_PACKET, errors.New("Broken INFO message - broken server info")
    }

    addr_count := len(data) / 6
    servers := make([]net.UDPAddr, addr_count)

    for idx := 0; idx < addr_count ; idx++ {
        port := binary.BigEndian.Uint16(data[4:6])
        servers[idx] = net.UDPAddr{net.IPv4(data[0], data[1], data[2], data[3]), int(port), ""}
        data = data[6:]
    }

    return &InfoMessage{addr, fname, servers}, ERR_OK, nil
}

func parseReadFileMessage(data []byte) (*ReadMessage, int, error) {
    fname_ends := bytes.IndexByte(data, byte(0))

    if fname_ends == -1 {
        return nil, ERR_BROKEN_PACKET, errors.New("Broken READ message - no 0 char after filename")
    }

    fname := string(data[:fname_ends])
    data = data[fname_ends + 1:]
    if len(data) != 16 {
        return nil, ERR_BROKEN_PACKET, errors.New("Broken READ message - not enought/too many data for offsets")
    }

    boffset := binary.BigEndian.Uint64(data)
    eoffset := binary.BigEndian.Uint64(data[8:])

    return &ReadMessage{fname, boffset, eoffset}, ERR_OK, nil
}
