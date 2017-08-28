package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

// 协议参考 https://zh.wikipedia.org/wiki/SOCKS

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
		// pln(conn)
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	chkType := read(conn, 2)
	if chkType[0] != 0x05 {
		log.Println("not socks5")
		return
	}

	methods := read(conn, int(chkType[1]))
	isSupport := false
	for _, v := range methods {
		if v == 0x00 {
			isSupport = true
			break
		}
	}

	if !isSupport {
		log.Println("只支持0x00无验证方式")
	}

	// 验证通过
	conn.Write([]byte{0x05, 0x00})

	// 读取请求，判断请求类型与目标类型
	reqType := read(conn, 4)
	if reqType[0] != 0x05 {
		log.Println("req not socks5")
		errReply(0x07)
		return
	}
	if reqType[1] != 0x01 {
		// 只处理connect请求
		errReply(0x07)
		return
	}
	if reqType[2] != 0x00 { // rsv 必须固定0x00
		return
	}
	var remoteHost string
	atyp := reqType[3]
	switch atyp {
	case 0x01:
		// ipv4
		dat := read(conn, 6)
		remoteHost = fmt.Sprintf("%d.%d.%d.%d:%d", dat[0], dat[1], dat[2], dat[3], int(dat[4])*256+int(dat[5]))
	case 0x03:
		// domain
		dat := read(conn, 1)
		tmpLen := int(dat[0])
		dat = read(conn, tmpLen+2)
		remoteHost = fmt.Sprintf("%s:%d", dat[0:tmpLen], int(dat[tmpLen])*256+int(dat[tmpLen+1]))
	case 0x04:
		// ipv6
		b := read(conn, 16)
		remoteHost = net.IP{b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}.String()
	}

	// 请求目标
	log.Printf("连接：%s\n", remoteHost)
	remoteConn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		log.Printf("连接：%s出错: %s\n", remoteHost, err)
		errReply(0x05)
	}
	defer remoteConn.Close()

	buf := make([]byte, 10)
	copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
	conn.Write(buf)
	// conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	go io.Copy(remoteConn, conn)
	io.Copy(conn, remoteConn)
}

func read(conn net.Conn, len int) []byte {
	data := make([]byte, len)
	if _, err := io.ReadFull(conn, data); err != nil {
		fmt.Println(err.Error())
	}

	return data
}

func errReply(rep byte) []byte {
	return []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}
