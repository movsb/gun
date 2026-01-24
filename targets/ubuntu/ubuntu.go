package ubuntu

import (
	"os"

	"github.com/movsb/gun/pkg/shell"
)

func Apt() {
	sh := shell.Bind(shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	sh.Run(`apt update`)

	for _, pkg := range []string{
		`iptables`,
		`ipset`,
	} {
		sh.Run(`apt-get install -y ${pkg}`, shell.WithValues(`pkg`, pkg))
	}
}
