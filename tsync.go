package main

import ("net"
        "strings")

type MyStatus struct {
    servers map[string]Server
    replay_sock *net.UDPConn
}

func sendError(conn *net.UDPConn, err_code int) {
    byte_send, err := conn.Write([]byte{byte(err_code)})
    if err != nil || byte_send != 1 {
        // log error
    }
}

func sendFile(conn *net.UDPConn, msg *ReadMessage) {

}

func process_client(pack *UDPPacket,
                    conn *net.UDPConn,
                    conn_done_ch chan *net.UDPConn,
                    info_requests_c chan *InfoMessage) {

    defer func () {conn_done_ch <- conn}()

    mtype := int(pack.data[0])

    switch mtype {
    case INFO:
        msg, code, err := parseInfoMessage(pack.data[1:], pack.addr)
        if err != nil {
            log.Debugf("Parse error from %s - %s", pack.addr.String(), err.Error())
            sendError(conn, code)
        } else {
            // request current info from info management process
            info_requests_c <- msg
        }

    case READ:
        msg, code, err := parseReadFileMessage(pack.data[1:])
        if err != nil {
            sendError(conn, code)
        } else {
            sendFile(conn, msg)
        }

    case ERROR:
        log.Debugf("Ignore error from %s", pack.addr.String())
        // ignore error packet to avoid error sending loop

    default:
        // log error packet
        sendError(conn, ERR_WRONG_CMD)
        log.Errorf("Unknown packet type %d from %s", mtype, pack.addr.String())
    }
}

func makeInfoReplay(addrs []string) []byte {
    return make([]byte, 0)
}

func process_info_request(stat *MyStatus, info_msg *InfoMessage) {
    // send info to addr
    // code can be optimized, with two linear scans and one sort
    remote_srv := make(map[string]bool)

    for _, srv_addr_obj := range info_msg.servers {
        srv_addr_s := srv_addr_obj.String()

        remote_srv[srv_addr_s] = true
        _, ok := stat.servers[srv_addr_s]
        if !ok {
            stat.servers[srv_addr_s] = Server{&srv_addr_obj}
        }
    }

    missing_remotelly := make([]string, len(stat.servers))

    for _, srv := range stat.servers {
        addr_s := srv.addr.String()
        _, ok := remote_srv[addr_s]
        if !ok {
            missing_remotelly = append(missing_remotelly, addr_s)
        }
    }

    stat.replay_sock.Write(makeInfoReplay(missing_remotelly))
}

func fill_fake_servers(stat *MyStatus) bool {
    fase_srv_addr := "127.0.1.1:12335"
    saddr, err := net.ResolveUDPAddr("udp", fase_srv_addr)
    if err != nil {
        log.Critical("Can't add fake server")
        return false
    }

    stat.servers[fase_srv_addr] = Server{saddr}
    return true
}

// listen_ip string
func MainLoop(listen_addr string) bool {
    colon_pos := strings.Index(listen_addr, ":")
    if -1 == colon_pos {
        log.Criticalf("Can't found ip:port in %s", listen_addr)
        return false
    }
    pool_sock_addr := listen_addr[:colon_pos] + ":0"

    stat := MyStatus{}
    stat.servers = make(map[string]Server)
    stat.replay_sock = makeUDPSock(pool_sock_addr)
    if stat.replay_sock == nil {
        return false
    }
    defer stat.replay_sock.Close()

    if !fill_fake_servers(&stat) {
        return false
    }

    new_conn_ch := make(chan *UDPPacket)
    free_conn_ch := make(chan *net.UDPConn)
    info_requests_c := make(chan *InfoMessage)

    go listen_udp_sock(listen_addr, new_conn_ch)

    conn_pool := []*net.UDPConn{}
    curr_free_pos := 0

    for {
        select {
        case info_msg := <- info_requests_c:
            log.Infof("Get info request from %s", info_msg.addr.String())
            process_info_request(&stat, info_msg)

        case pack := <- new_conn_ch:
            log.Debugf("New packet received - %d bytes from %s", len(pack.data), pack.addr.String())
            var conn *net.UDPConn
            if curr_free_pos == 0 {
                conn = makeUDPSock(pool_sock_addr)
                if conn == nil {
                    break
                }
            } else {
                conn = conn_pool[curr_free_pos - 1]
                curr_free_pos--
            }
            go process_client(pack, conn, free_conn_ch, info_requests_c)

        case freed_conn := <- free_conn_ch:
            log.Debugf("Conn freed ", freed_conn.LocalAddr().String())
            if curr_free_pos == len(conn_pool) {
                conn_pool = append(conn_pool, freed_conn)
            } else {
                conn_pool[curr_free_pos] = freed_conn
            }
            curr_free_pos++
        }
    }

    return true
}

