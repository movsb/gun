package targets

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Arch(update bool) {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	if update {
		sh.Run(`pacman -Sy`)
	}

	sh.Run(`pacman -S --noconfirm --needed ca-certificates`)

	if !hasGroupAdd() {
		sh.Run(`pacman -S --noconfirm --needed shadow`)
	}

	if !hasCommand(`sysctl`) {
		sh.Run(`pacman -S --noconfirm --needed procps-ng`)
	}

	if !hasCommand(`setcap`) {
		sh.Run(`pacman -S --noconfirm --needed libcap`)
	}

	if !hasCommand(`ip`) {
		sh.Run(`pacman -S --noconfirm --needed iproute2`)
	}

	if !hasCommand(`ipset`) {
		sh.Run(`pacman -S --noconfirm --needed ipset`)
	}

	if !hasCommand(`iptables`) {
		sh.Run(`pacman -S --noconfirm --needed iptables`)
	}

	// 没有检查内核模块存在情况。
}
