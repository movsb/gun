//go:build !linux

package tproxy

import "net"

func listenAndServeTCP(port uint16, handler func(conn net.Conn, remote string)) {
	panic(`only for linux`)
}
