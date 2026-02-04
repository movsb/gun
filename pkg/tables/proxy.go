package tables

import (
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
)

const (
	DNSPort          = 60053
	OutputsGroupName = `_gun_outputs`
	DNSGroupName     = `_gun_dns`
)

// 接管系统/内网主机的DNS请求（重定向）。
func ProxyDNS(cmd string, family Family) {
	sh := shell.Bind(
		chainNames,
		shell.WithValues(
			`cmd`, cmd,
			`outputsGroupName`, OutputsGroupName,
			`dnsGroupName`, DNSGroupName,
			`addr`, utils.IIF(family == IPv4, `127.0.0.1`, `::1`),
			`port`, DNSPort,
		),
	)

	// 本机其它进程发出的DNS请求转发到本DNS服务器。
	//
	// DNS服务器本身的请求不会循环到自身来（查询风暴）、代理进程组的请求也不来。
	// 所以，不用担心代理进程的域名的解析靠本DNS解析然后陷入死循环。
	//
	// --syn 用于建立首包 conntrack 映射，后续 TCP 包由 conntrack 自动沿用映射，因此不需要再匹配规则。
	sh.Run(`${cmd} -t nat -A ${output} \
		-p tcp -m tcp --dport 53 --syn \
		-m owner ! --gid-owner ${outputsGroupName} \
		-m owner ! --gid-owner ${dnsGroupName} \
		-j REDIRECT --to-ports ${port}`,
	)

	// 在 netfilter 里，conntrack 不是“TCP 专用”，UDP 也有连接跟踪。
	// NEW 表示 UDP 新“连接”的第一个包，后续**超时窗口内的包**被认为是 ESTABLISHED。
	// 通过 `sysctl net.netfilter.nf_conntrack_udp_timeout_stream` 可以查看窗口超时大小。
	sh.Run(`${cmd} -t nat -A ${output} \
		-p udp -m udp --dport 53 \
		-m conntrack --ctstate NEW \
		-m owner ! --gid-owner ${outputsGroupName} \
		-m owner ! --gid-owner ${dnsGroupName} \
		-j REDIRECT --to-ports ${port}`,
	)

	// REDIRECT 只修改目的地址； 当流量被重定向到 loopback 时，必须在 POSTROUTING
	// 用 SNAT 将源地址也改为 loopback，否则会产生不可靠的回包行为。
	//
	// 可以考虑换成 tproxy？
	sh.Run(`${cmd} -t nat -A ${postrouting} \
		-d ${addr} ! -s ${addr} \
		-j SNAT --to-source ${addr}`,
	)

	// 内网其它主机发来的DNS请求，转到DNS进程。
	sh.Run(`${cmd} -t nat -A ${prerouting} \
		-p tcp -m tcp --dport 53 --syn \
		-m addrtype ! --src-type LOCAL \
		-j REDIRECT --to-ports ${port}`,
	)
	sh.Run(`${cmd} -t nat -A ${prerouting} \
		-p udp -m udp --dport 53 \
		-m conntrack --ctstate NEW \
		-m addrtype ! --src-type LOCAL \
		-j REDIRECT --to-ports ${port}`,
	)
}

const (
	TPROXY_SERVER_IP_4 = `127.0.0.1`
	TPROXY_SERVER_IP_6 = `::1`
	TPROXY_SERVER_PORT = 60080

	// gun， 不能太大，否则 ip rule del table 报错
	TPROXY_TABLE = 486
	TPROXY_MARK  = `0x486`
)

var tproxyValues = shell.WithMaps(map[string]any{
	`TPROXY_SERVER_IP_4`: TPROXY_SERVER_IP_4,
	`TPROXY_SERVER_IP_6`: TPROXY_SERVER_IP_6,
	`TPROXY_SERVER_PORT`: TPROXY_SERVER_PORT,
	`TPROXY_MARK`:        TPROXY_MARK,
})

// 会总是开启TCP。
func TProxy(cmd string, family Family) {
	sh := shell.Bind(
		shell.WithValues(`cmd`, cmd,
			`blackSetName`, utils.IIF(family == IPv4, BLACK_SET_NAME_4, BLACK_SET_NAME_6),
			`whiteSetName`, utils.IIF(family == IPv4, WHITE_SET_NAME_4, WHITE_SET_NAME_6),
		),
		chainNames,
		tproxyValues,
		shell.WithValues(
			`outputsGroupName`, OutputsGroupName,
			`dnsGroupName`, DNSGroupName,
		),
	)

	// 放行流量：如果ip在白名单中且不在黑名单中。
	// 并且打上标记，以便策略路由到本机。
	sh.Run(`${cmd} -t mangle -A ${rule} \
		-m set --match-set ${whiteSetName} dst \
		-m set ! --match-set ${blackSetName} dst \
		-j RETURN`,
	)
	sh.Run(`${cmd} -t mangle -A ${rule}  -j CONNMARK --set-mark ${TPROXY_MARK}`)

	// 放行发给本机进程的流量（以及回复流量）。
	sh.Run(`${cmd} -t mangle -A ${output} -m addrtype --dst-type LOCAL -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${output} -m conntrack --ctdir REPLY -j RETURN`)

	// 放行本机代理进程传出的流量。
	sh.Run(`${cmd} -t mangle -A ${output} -m owner --gid-owner ${outputsGroupName} -j RETURN`)

	// 放行：除DNS进程、上面的代理进程外所有的DNS请求。交给上面的DNS重定向。
	// --dport 是 -p tcp / -p udp 各自的扩展，好像没法合并一起写。
	sh.Run(`${cmd} -t mangle -A ${output} -p tcp -m tcp --dport 53 -m owner ! --gid-owner ${dnsGroupName} -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${output} -p udp -m udp --dport 53 -m owner ! --gid-owner ${dnsGroupName} -j RETURN`)

	// 接管本机传出的流量。
	sh.Run(`${cmd} -t mangle -A ${output} -p tcp -m tcp --syn -j ${rule}`)
	sh.Run(`${cmd} -t mangle -A ${output} -p udp -m conntrack --ctstate NEW,RELATED -j ${rule}`)
	// 打上标记以进入本地路由表（prerouting）。
	sh.Run(`${cmd} -t mangle -A ${output} -m connmark --mark ${TPROXY_MARK} -j MARK --set-mark ${TPROXY_MARK}`)

	// 放行发往本机的流量。
	sh.Run(`${cmd} -t mangle -A ${prerouting} -m addrtype --dst-type LOCAL -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${prerouting} -m conntrack --ctdir REPLY -j RETURN`)

	// 接管内网主机传出的流量。
	sh.Run(`${cmd} -t mangle -A ${prerouting} \
		-p tcp -m tcp --syn ! --dport 53 \
		-m addrtype ! --src-type LOCAL \
		-j ${rule}`,
	)
	sh.Run(`${cmd} -t mangle -A ${prerouting} \
		-p udp -m udp ! --dport 53 \
		-m conntrack --ctstate NEW,RELATED \
		-m addrtype ! --src-type LOCAL \
		-j ${rule}`,
	)

	// 正式用 tproxy 接管。
	tsh := sh.Bind(shell.WithValues(`ip`, utils.IIF(family == 4, TPROXY_SERVER_IP_4, TPROXY_SERVER_IP_6), `port`, TPROXY_SERVER_PORT))
	tsh.Run(`${cmd} -t mangle -A ${prerouting} -p tcp -m connmark --mark ${TPROXY_MARK} -j TPROXY --on-ip ${ip} --on-port ${port} --tproxy-mark ${TPROXY_MARK}`)
	tsh.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m connmark --mark ${TPROXY_MARK} -j TPROXY --on-ip ${ip} --on-port ${port} --tproxy-mark ${TPROXY_MARK}`)
}

func DropQUIC(cmd string, family Family) {
	sh := shell.Bind(
		chainNames,
		shell.WithValues(`cmd`, cmd,
			`blackSetName`, utils.IIF(family == 4, BLACK_SET_NAME_4, BLACK_SET_NAME_6),
			`whiteSetName`, utils.IIF(family == 4, WHITE_SET_NAME_4, WHITE_SET_NAME_6),
			`outputsGroupName`, OutputsGroupName,
		),
	)

	sh.Run(`${cmd} -t mangle -A ${quic} -m set --match-set ${whiteSetName} dst -m set ! --match-set ${blackSetName} dst -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${quic} -j DROP`)

	sh.Run(`${cmd} -t mangle -A ${output} -p udp -m udp --dport 443 -m conntrack --ctdir ORIGINAL -m addrtype ! --dst-type LOCAL -m owner ! --gid-owner ${outputsGroupName} -j ${quic}`)
	sh.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m udp --dport 443 -m conntrack --ctdir ORIGINAL -m addrtype ! --dst-type LOCAL -j ${quic}`)
}
