package trojan

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/movsb/gun/inputs/tproxy"
	"github.com/movsb/gun/pkg/utils"
)

type Trojan struct {
	// 真实的 host:port
	ServerAddrPort string
	// 密码。
	Password string
	// 是否不校验证书安全性。
	InsecureSkipVerify bool
	// 伪装的 SNI
	ServerName string
}

func ListenAndServeTProxy(
	port uint16,
	serverAddrPort string,
	password string,
	insecureSkipVerify bool,
	serverName string,
) {
	tr := Trojan{
		ServerAddrPort:     serverAddrPort,
		Password:           password,
		InsecureSkipVerify: insecureSkipVerify,
		ServerName:         serverName,
	}
	tr.ListenAndServeTProxy(port)
}

func (t *Trojan) ListenAndServeTProxy(port uint16) {
	tproxy.ListenAndServeTCP(port, func(conn net.Conn) {
		remoteAddrStr := conn.LocalAddr().String()
		t.ProxyTCP4(conn, netip.MustParseAddrPort(remoteAddrStr))
	})
}

func (t *Trojan) ProxyTCP4(local net.Conn, remote netip.AddrPort) error {
	defer local.Close()

	remoteConn, err := tls.Dial(`tcp4`, t.ServerAddrPort, &tls.Config{
		InsecureSkipVerify: t.InsecureSkipVerify,
		ServerName:         t.ServerName,
	})
	if err != nil {
		return fmt.Errorf(`trojan: %w`, err)
	}
	defer remoteConn.Close()

	back := [256]byte{}
	buf := bytes.NewBuffer(back[:0])

	// 写密码
	pswSum := sha256.Sum224([]byte(t.Password))
	buf.WriteString(hex.EncodeToString(pswSum[:]))
	buf.WriteString("\r\n")

	// 写请求
	buf.WriteByte(1) // CONNECT
	if remote.Addr().Is4() {
		buf.WriteByte(1)
		ip4 := remote.Addr().As4()
		buf.Write(ip4[:])
	} else if remote.Addr().Is6() {
		buf.WriteByte(4)
		ip6 := remote.Addr().As16()
		buf.Write(ip6[:])
	} else {
		log.Fatalln(`不支持的地址类型。`)
	}
	buf.Write(binary.BigEndian.AppendUint16(nil, remote.Port()))
	buf.WriteString("\r\n")

	// 写首包数据。
	// “This avoids length pattern detection and may reduce the number of packets to be sent.”
	initial := [512]byte{}
	local.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	if n, err := local.Read(initial[:]); err != nil {
		return fmt.Errorf(`读首包数据时错误：%w`, err)
	} else {
		buf.Write(initial[:n])
		local.SetReadDeadline(time.Time{})
	}

	if _, err := remoteConn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf(`trojan: 写请求时失败：%w`, err)
	}

	utils.Stream(local, remoteConn)

	return nil
}
