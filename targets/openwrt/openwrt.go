package openwrt

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Opkg() {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	sh.Run(`opkg update`)

	for _, pkg := range []string{
		`iptables-legacy`,
		`ip6tables-legacy`,
		`ip6tables-zz-legacy`,
		`ipset`,
		`kmod-ipt-conntrack`,
		`iptables-mod-conntrack-extra`,
		`iptables-mod-extra`, // for addrtype
		`kmod-ipt-nat`,
		`kmod-ipt-nat6`,
		`shadow-groupadd`,
		`iptables-mod-tproxy`,
	} {
		sh.Run(`opkg install ${pkg}`, shell.WithValues(`pkg`, pkg))
	}
}
