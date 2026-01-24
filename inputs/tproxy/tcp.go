//go:build linux

package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/movsb/gun/pkg/utils"
)

// [kernel.org/doc/Documentation/networking/tproxy.txt](https://www.kernel.org/doc/Documentation/networking/tproxy.txt)

func ListenTCP(network string, local *net.TCPAddr) (net.Listener, error) {
	listener, err := net.ListenTCP(network, local)
	if err != nil {
		return nil, err
	}
	lfd, err := listener.File()
	if err != nil {
		return nil, &net.OpError{Op: `listen`, Net: network, Source: nil, Addr: local, Err: err}
	}
	defer lfd.Close()

	// 虽然文档说的是要在bind之前设置，但是我在这里设置实际上也能成功。
	if err := syscall.SetsockoptInt(int(lfd.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return nil, &net.OpError{Op: `listen`, Net: network, Source: nil, Addr: local, Err: err}
	}

	return listener, nil
}

func main() {
	l := utils.Must1(ListenTCP(`tcp4`, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(`127.0.0.1:60080`))))
	defer l.Close()

	for {
		conn := utils.Must1(l.Accept())
		log.Println(conn.LocalAddr(), conn.RemoteAddr())
		// conn.Close()
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.LocalAddr()

	remote, err := net.Dial(`tcp4`, `localhost:1080`)
	if err != nil {
		log.Println(err)
		return
	}
	defer remote.Close()

	remote.Write([]byte{5, 1, 0})

	buf := make([]byte, 128)
	io.ReadFull(remote, buf[:2])
	if buf[0] != 5 || buf[1] != 0 {
		log.Println(`服务器错误`)
		return
	}

	host, port, _ := net.SplitHostPort(remoteAddr.String())
	remote.Write([]byte{5, 1, 0, 1})
	remote.Write(net.ParseIP(host).To4())
	binary.BigEndian.PutUint16(buf, uint16(utils.Must1(strconv.Atoi(port))))
	remote.Write(buf[:2])

	io.ReadAtLeast(remote, buf, 10)
	if buf[0] != 5 || buf[1] != 0 || buf[2] != 0 {
		log.Println(`连接错误`, buf)
		return
	}

	ch := make(chan struct{})

	go func() {
		io.Copy(conn, remote)
		ch <- struct{}{}
	}()
	go func() {
		io.Copy(remote, conn)
		ch <- struct{}{}
	}()

	<-ch
}
