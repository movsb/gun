package targets

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func OpenWRT(major int) {
	if major >= 25 {
		sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))
		sh.Run(`apk update`)
		run(func(pkg string) {
			sh.Run(`apk add ${pkg}`, shell.WithValues(`pkg`, pkg))
		})
	}
	if major <= 24 {
		sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))
		sh.Run(`opkg update`)
		run(func(pkg string) {
			sh.Run(`opkg install ${pkg}`, shell.WithValues(`pkg`, pkg))
		})
	}
}

func run(install func(pkg string)) {
	install(`ca-certificates`)

	if !hasGroupAdd() {
		install(`shadow-groupadd`)
	}

	if !hasCommand(`sysctl`) {
		install(`procps-ng-sysctl`)
	}

	if !hasCommand(`setcap`) {
		install(`libcap-bin`)
	}

	if !hasCommand(`ip`) {
		install(`ip-full`)
	}

	if !hasCommand(`ipset`) {
		install(`ipset`)
	}

	if !hasCommand(`iptables`) {
		install(`iptables-nft`)
	}
	if !hasCommand(`ip6tables`) {
		install(`ip6tables-nft`)
	}

	for _, pkg := range []string{
		`kmod-ipt-conntrack`,
		`iptables-mod-conntrack-extra`,
		`iptables-mod-extra`, // for addrtype
		`kmod-ipt-nat`,
		`kmod-ipt-nat6`,
		`iptables-mod-tproxy`,
	} {
		install(pkg)
	}
}
