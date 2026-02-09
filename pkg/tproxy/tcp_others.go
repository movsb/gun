//go:build !linux

package tproxy

import "net"

func ListenAndServeTCP(port uint16, handler func(conn net.Conn)) {
	panic(`not fot darwin`)
}
