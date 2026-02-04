package tables

import "github.com/movsb/gun/pkg/shell"

func CreateIPRoute(family Family) {
	sh := shell.Bind(shell.WithValues(
		`family`, family,
		`table`, TPROXY_TABLE,
		`mark`, TPROXY_MARK,
	))

	// 允许打了mark的走我们的表查策略路由并进入本地。
	// https://www.kernel.org/doc/Documentation/networking/tproxy.txt
	//
	// 和内核参数的 route_localnet 重复了吗？
	//
	// 不会重复，但它们是同一功能链条上的不同环节，作用层级完全不同。
	//
	// 一、前面的 route_localnet=1
	//
	//     sysctl -w net.ipv4.conf.all.route_localnet=1
	//
	// 作用：
	//
	//   • 内核允许从外部接口进入的包，被路由到本地回环地址（127/8），解决的是 安全检查限制
	//   • 默认情况下，内核会丢掉“发到 127.0.0.1 但从 eth0 进来的包”。
	//   • 它 不产生路由表 / 规则，相当于给 TPROXY 做“安全放行许可”。
	//
	// 二、下面两句（policy routing / TPROXY 路由）
	//
	//     ip rule add fwmark 1 lookup 100
	//     ip route add local 0.0.0.0/0 dev lo table 100
	//
	// 作用：
	//
	//      1.ip rule add fwmark 1 lookup 100
	//
	//      • 把打了 mark=1 的数据包交给 routing table 100 处理
	//      • 这是 policy routing，按 fwmark 选择路由表
	//
	//      2. ip route add local 0.0.0.0/0 dev lo table 100
	//
	//      • 给 table 100 添加一条路由：所有目的地址 → local
	//      • 内核会把这些包送到 本地 socket。
	//      • 这是 TPROXY 核心：保留原始目标 IP，同时把包交给本地进程
	//
	// 理解方式：route_localnet 是“安全开关”，ip rule/ip route 是“路由指令”。
	sh.Run(`ip -${family} rule add fwmark ${mark} table ${table}`)
	sh.Run(`ip -${family} route add local default dev lo table ${table}`)
}

func DeleteIPRoute(family Family) {
	sh := shell.Bind(
		shell.WithValues(
			`family`, family,
			`table`, TPROXY_TABLE,
			`mark`, TPROXY_MARK,
		),
		shell.WithIgnoreErrors(
			`No such file or directory`,
			`No such process`,
			`table does not exist`,
		),
	)

	// 在 OpenWRT/24.10.5 上出现过 flush 之后 add 仍然显示已存在的问题，
	// 所以 flush 之后再尝试 del 一下。
	sh.Run(`ip -${family} rule  del   table ${table}`)
	sh.Run(`ip -${family} route flush table ${table}`)
	sh.Run(`ip -${family} route del   table ${table}`)
}
