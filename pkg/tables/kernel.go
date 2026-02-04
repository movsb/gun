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
func SetKernelParams() {
	// 允许转发，即：充当网关。
	// 允许转发后，从其它主机进来的包才不会被内核丢弃，才能进入PREROUTING。
	// IPv4下有总开关，可以全局配置；IPv6下权限细分开了，需要按每个接口独立配置。
	shell.Run(`sysctl -wq net.ipv4.ip_forward=1`)
	_sysctlAllInterfaces(IPv6, `forwarding=1`)

	// 允许“从外部接口进入的流量，被路由到本地回环地址”
	//
	// TPROXY 会把“目的地址不是本机”的流量，重定向到本机 socket；
	// 而 Linux 默认认为“发往 127.0.0.0/8 的包不能从非 lo 接口进来”，
	// 这是为了防止：
	//   - IP spoofing
	//   - 外部主机伪造 127.0.0.1
	//   - 绕过防火墙、ACL
	// route_localnet=1 就是解除这条安全限制。
	//
	// 如果不开它，包在进 socket 之前就被内核丢了。
	//
	// TPROXY 不是 DNAT，它是：
	//   - 保留原始目的 IP / port
	//   - 只是在路由阶段：
	//   - 把包送给本地 socket
	//   - 并且允许程序 getsockopt(SO_ORIGINAL_DST)
	//
	// 内核会认为：
	//
	// “这个包来自 eth0，却要进一个绑定在 127.0.0.1 的 socket？”
	//
	// 默认：直接丢
	//
	// DNAT不需要这个：因为它直接把包改成127了，内核直接认为是本地发本地。
	_sysctlAllInterfaces(IPv4, `route_localnet=1`)

	// 控制 内核是否对路由变动发送 ICMP Redirect 消息。
	//
	// Linux 默认 send_redirects=1，当内核发现某个包本来可以通过另一条路由更直接到达目标时，
	// 内核会 发送 ICMP Redirect 给源主机告诉它：“下次直接走这条路”。
	//
	// 例子：
	//
	//   - 客户端 10.0.0.2
	//   - 网关  10.0.0.1 （你机器）
	//   - 目标  10.0.0.3
	//
	// 如果 10.0.0.2 发包到 10.0.0.3 经 10.0.0.1，内核可能发 ICMP Redirect
	// 告诉 10.0.0.2：“直接走 10.0.0.3 的网关更快”。
	//
	// 然后，客户端就直连目标了，绕开了 tproxy。
	_sysctlAllInterfaces(IPv4, `send_redirects=0`)
}

func _sysctlAllInterfaces(family Family, kv string) {
	paths := utils.Must1(filepath.Glob(fmt.Sprintf(`/proc/sys/net/ipv%d/conf/*`, family)))
	for _, path := range paths {
		conf := strings.TrimPrefix(path, `/proc/sys/`)
		shell.Run(`sysctl -wq ${conf}/${kv}`, shell.WithValues(`conf`, conf, `kv`, kv))
	}
}
