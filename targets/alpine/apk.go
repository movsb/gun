package alpine

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Apk() {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	sh.Run(`apk update`)

	for _, pkg := range []string{
		`iptables-legacy`,
		`ipset`,
	} {
		sh.Run(`apk add ${pkg}`, shell.WithValues(`pkg`, pkg))
	}
}
