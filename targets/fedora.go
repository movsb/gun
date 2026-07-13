package targets

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Fedora(update bool) {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	if update {
		sh.Run(`dnf upgrade -y`)
	}

	sh.Run(`dnf install -y ca-certificates`)

	if !hasGroupAdd() {
		sh.Run(`dnf install -y shadow-utils`)
	}

	if !hasCommand(`sysctl`) {
		sh.Run(`dnf install -y procps-ng`)
	}

	if !hasCommand(`setcap`) {
		sh.Run(`dnf install -y libcap`)
	}

	if !hasCommand(`ip`) {
		sh.Run(`dnf install -y iproute`)
	}

	if !hasCommand(`ipset`) {
		sh.Run(`dnf install -y ipset`)
	}

	if !hasCommand(`iptables`) {
		sh.Run(`dnf install -y iptables-nft`)
	}

	// 没有检查内核模块存在情况。
}
