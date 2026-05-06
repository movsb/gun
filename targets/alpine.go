package targets

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Alpine() {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	sh.Run(`apk update`)

	sh.Run(`apk add ca-certificates`)

	if !hasGroupAdd() {
		sh.Run(`apk add shadow`)
	}

	if !hasCommand(`sysctl`) {
		sh.Run(`apk add procps-ng`)
	}

	if !hasCommand(`setcap`) {
		sh.Run(`apk add libcap-setcap`)
	}

	if !hasCommand(`ip`) {
		sh.Run(`apk add iproute2`)
	}

	if !hasCommand(`ipset`) {
		sh.Run(`apk add ipset`)
	}

	if !hasCommand(`iptables`) {
		sh.Run(`apk add iptables`)
	}

	// 没有检查内核模块存在情况。
}
