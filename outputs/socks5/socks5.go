package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// [SOCKS - Wikipedia](https://en.wikipedia.org/wiki/SOCKS#SOCKS5)

func ProxyTCP4Addr(conn net.Conn, serverAddr string, dstAddr string) error {
	remote, err := net.Dial(`tcp4`, serverAddr)
	if err != nil {
		return fmt.Errorf(`连接SOCKS5服务器失败：%s: %w`, serverAddr, err)
	}
	return ProxyTCP4Conn(conn, remote, dstAddr)
}

func ProxyTCP4Conn(local, remote net.Conn, dstAddr string) error {
	defer local.Close()
	defer remote.Close()

	dst := netip.MustParseAddrPort(dstAddr)

	buf := [128]byte{}

	// 无密码问候。
	if _, err := remote.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf(`协议错误：%w`, err)
	}

	// 读无密码响应。
	if _, err := io.ReadFull(remote, buf[:2]); err != nil {
		return fmt.Errorf(`协议错误：%w`, err)
	}
	if !(buf[0] == 5 && buf[1] == 0x00) {
		return fmt.Errorf(`服务器认证不支持。`)
	}

	// 建立TCP连接。
	buf[0] = 5
	buf[1] = 1
	buf[2] = 0
	buf[3] = 1
	copy(buf[4:], dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(buf[8:], dst.Port())
	if _, err := remote.Write(buf[:10]); err != nil {
		return fmt.Errorf(`协议错误：%w`, err)
	}

	// 读连接状态。
	if _, err := io.ReadFull(remote, buf[:10]); err != nil {
		return fmt.Errorf(`协议错误：%w`, err)
	}
	if !(buf[0] == 5 && buf[1] == 0 && buf[2] == 0) {
		return fmt.Errorf(`服务器连接错误：%v`, buf[:10])
	}

	// 可以接管连接了。
	ch := make(chan struct{})

	go func() {
		io.Copy(local, remote)
		ch <- struct{}{}
	}()
	go func() {
		io.Copy(remote, local)
		ch <- struct{}{}
	}()

	<-ch

	return nil
}
