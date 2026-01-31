package http2socks

import (
	"log"
	"net"

	"github.com/movsb/gun/inputs/tproxy"
	"github.com/movsb/gun/outputs/socks5"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/http2socks"
)

func ListenAndServeTProxy(port uint16, server, token string) {
	client := http2socks.NewClient(
		utils.MustGetEnvString(`SERVER`),
		utils.MustGetEnvString(`TOKEN`),
	)
	tproxy.ListenAndServeTCP(port, func(conn net.Conn) {
		socksConn, err := client.OpenConn()
		if err != nil {
			log.Println(err)
			return
		}
		remote := conn.LocalAddr().String()
		socks5.ProxyTCP4Conn(conn, socksConn, remote)
	})
}
