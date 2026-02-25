//go:build !linux

package tproxy

import "net"

// net.Conn.LocalAddr 是本来要连接的远程地址。
// handler 是在独立的线程中被调用的。
func ListenAndServeTCP(port uint16, handler func(conn net.Conn, remote string)) {
	panic(`not fot darwin`)
}
