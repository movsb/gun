//go:build linux

package dns

import (
	"log"
	"net/netip"

	"github.com/movsb/gun/pkg/utils"
	"github.com/nadoo/ipset"
)

func init() {
	utils.Must(ipset.Init())
}

func AddIPSet(name string, ip netip.Addr) {
	opts := []ipset.Option{}
	if ip.Is6() {
		opts = append(opts, ipset.OptIPv6())
	}
	if err := ipset.AddAddr(name, ip, opts...); err != nil {
		log.Println(`未能将IP添加到名单：`, name, err)
	} else {
		log.Println(`已将IP添加到名单：`, name, ip)
	}
}
