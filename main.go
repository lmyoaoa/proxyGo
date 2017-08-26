package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

var pln = fmt.Println

func main() {
	// 监听本机端口
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatal("Listen error: ", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		pln(conn)
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	pln(addr)
	defer func() {
		conn.Close()
	}()

	buf1 := readBytes(conn, 2)
	pln(buf1)
	if buf1[0] != 0x05 {
		pln("类型不对，不是socks5")
		return
	}

	nom := int(buf1[1]) // number of methods
	methods := readBytes(conn, nom)
	var support bool
	for _, meth := range methods {
		if meth == 0x00 {
			support = true
			break
		}
	}
	if !support {
		// X'FF' NO ACCEPTABLE METHODS
		conn.Write([]byte{0x05, 0xff})
		return
	}

	// X'00' NO AUTHENTICATION REQUIRED
	conn.Write([]byte{0x05, 0x00})

	// recv command packet
	buf3 := readBytes(conn, 4)
	protocolCheck(buf3[0] == 0x05) // VER
	protocolCheck(buf3[2] == 0x00) // RSV

	command := buf3[1]
	if command != 0x01 { // 0x01: CONNECT
		// X'07' Command not supported
		conn.Write(errorReplyConnect(0x07))
		return
	}

	addrtype := buf3[3]
	if addrtype != 0x01 && addrtype != 0x03 {
		// X'08' Address type not supported
		conn.Write(errorReplyConnect(0x08))
		return
	}

	var backend string
	if addrtype == 0x01 { // 0x01: IP V4 address
		buf4 := readBytes(conn, 6)
		backend = fmt.Sprintf("%d.%d.%d.%d:%d", buf4[0], buf4[1],
			buf4[2], buf4[3], int(buf4[4])*256+int(buf4[5]))
	} else if addrtype == 0x04 { // 支持ipv6
		b := buf1
		backend = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
	} else { // 0x03: DOMAINNAME
		buf4 := readBytes(conn, 1)
		nmlen := int(buf4[0]) // domain name length
		if nmlen > 253 {
			panic("domain name too long") // will be recovered
		}

		buf5 := readBytes(conn, nmlen+2)
		backend = fmt.Sprintf("%s:%d", buf5[0:nmlen],
			int(buf5[nmlen])*256+int(buf5[nmlen+1]))
	}

	log.Printf("connect to %s...\n", backend)
	backconn, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("failed to connect to %s: %s\n", backend, err)
		conn.Write(errorReplyConnect(0x05))
		return
	}
	defer func() {
		backconn.Close()
	}()

	buf := make([]byte, 10)
	copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
	packNetAddr(backconn.RemoteAddr(), buf[4:])
	conn.Write(buf)

	go io.Copy(backconn, conn)
	io.Copy(conn, backconn)
}

func readBytes(conn io.Reader, count int) (buf []byte) {
	buf = make([]byte, count)
	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Println(err.Error())
	}
	return
}

func protocolCheck(assert bool) {
	if !assert {
		panic("protocol error")
	}
}

func errorReplyConnect(reason byte) []byte {
	return []byte{0x05, reason, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// Convert a IP:Port string to a byte array in network order.
// e.g.: 74.125.31.104:80 -> [74 125 31 104 0 80]
func packNetAddr(addr net.Addr, buf []byte) {
	ipport := addr.String()
	pair := strings.Split(ipport, ":")
	ipstr, portstr := pair[0], pair[1]
	port, err := strconv.Atoi(portstr)
	if err != nil {
		panic(fmt.Sprintf("invalid address %s", ipport))
	}

	copy(buf[:4], net.ParseIP(ipstr).To4())
	buf[4] = byte(port / 256)
	buf[5] = byte(port % 256)
}
