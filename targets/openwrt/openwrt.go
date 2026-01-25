package openwrt

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Apk() {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))
	sh.Run(`apk update`)
	run(func(pkg string) {
		sh.Run(`apk add ${pkg}`, shell.WithValues(`pkg`, pkg))
	})
}
func Opkg() {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))
	sh.Run(`opkg update`)
	run(func(pkg string) {
		sh.Run(`opkg install ${pkg}`, shell.WithValues(`pkg`, pkg))
	})
}

func run(install func(pkg string)) {
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
		install(pkg)
	}
}
