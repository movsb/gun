//go:build linux

package tproxy

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// [kernel.org/doc/Documentation/networking/tproxy.txt](https://www.kernel.org/doc/Documentation/networking/tproxy.txt)
// [heiher/hev-socks5-tproxy: A lightweight, fast and reliable socks5 transparent proxy](https://github.com/heiher/hev-socks5-tproxy?tab=readme-ov-file#netfilter-and-routing)

// Accept到的net.Conn.LocalAddr 是本来要连接的远程地址。
func ListenTCP(port uint16) (net.Listener, error) {
	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf(`127.0.0.1:%d`, port)))
	return listenTCP(`tcp4`, addr)
}

func listenTCP(network string, local *net.TCPAddr) (net.Listener, error) {
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
