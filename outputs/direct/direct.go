package direct

import (
	"log"
	"net"

	"github.com/movsb/gun/pkg/tproxy"
	"github.com/movsb/gun/pkg/utils"
)

func ListenAndServeTProxy(port uint16) {
	tproxy.ListenAndServeTCP(port, func(conn net.Conn, addr string) {
		defer conn.Close()
		remote, err := net.Dial(`tcp`, addr)
		if err != nil {
			log.Println(err)
			return
		}
		defer remote.Close()
		utils.Stream(conn, remote)
	})
}
