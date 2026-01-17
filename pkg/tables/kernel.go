package tables

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
)

type Family int

const (
	IPv4 = Family(4)
	IPv6 = Family(6)
)

// 开启内核参数，允许数据库包转发。
func SetKernelParams(v4, v6 bool) {
	if v4 {
		shell.Run(`sysctl -wq net.ipv4.ip_forward=1`)
	}
	if v6 {
		_sysctlAllInterfaces(IPv6, `forwarding=1`)
	}

	_sysctlAllInterfaces(IPv4, `route_localnet=1`)
	_sysctlAllInterfaces(IPv4, `send_redirects=0`)
}

func _sysctlAllInterfaces(family Family, kv string) {
	paths := utils.Must1(filepath.Glob(fmt.Sprintf(`/proc/sys/net/ipv%d/conf/*`, family)))
	for _, path := range paths {
		conf := strings.TrimPrefix(path, `/proc/sys/`)
		shell.Run(`sysctl -wq ${conf}/${kv}`, shell.WithValues(`conf`, conf, `kv`, kv))
	}
}
