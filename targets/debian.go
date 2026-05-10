package targets

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Debian(update bool) {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	if update {
		sh.Run(`apt update`)
	}

	sh.Run(`apt-get install -y ca-certificates`)

	if !hasGroupAdd() {
		sh.Run(`apt-get install -y passwd`)
	}

	if !hasCommand(`sysctl`) {
		sh.Run(`apt-get install -y procps`)
	}

	if !hasCommand(`setcap`) {
		sh.Run(`apt-get install -y libcap2-bin`)
	}

	if !hasCommand(`ip`) {
		sh.Run(`apt-get install -y iproute2`)
	}

	if !hasCommand(`ipset`) {
		sh.Run(`apt-get install -y ipset`)
	}

	if !hasCommand(`iptables`) {
		sh.Run(`apt-get install -y iptables`)
	}

	// 没有检查内核模块存在情况。
}
