package main

import "net"

const MAX_PACKET_SIZE = 1400

type UDPPacket struct {
    data []byte
    addr *net.UDPAddr
}

func makeUDPSock(addr string) *net.UDPConn {
    log.Debugf("Creating %s", addr)
    saddr, err := net.ResolveUDPAddr("udp", addr)
    if err != nil {
        log.Criticalf("Can't resolve %s: %s", addr, err.Error())
        return nil
    }

    replay_sock, err := net.ListenUDP("udp", saddr)
    if err != nil {
        log.Criticalf("Can't create udp sock for %s: %s", addr, err.Error())
        return nil
    }
    return replay_sock
}

func listen_udp_sock(listen_addr string, packets_ch chan *UDPPacket) {
    log.Debugf("Start listening on %s", listen_addr)

    srv_listener := makeUDPSock(listen_addr)
    if srv_listener == nil {
        return
    }
    defer srv_listener.Close()

    for {
        buf := make([]byte, MAX_PACKET_SIZE)
        nbytes, addr, err := srv_listener.ReadFromUDP(buf)
        if err != nil {
            log.Criticalf("ReadFromUDP error: %s", err.Error())
            return
        }
        packets_ch <- &UDPPacket{buf[:nbytes], addr}
    }
}


