package tables

import (
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
)

const DNSPort = 60053

func ProxyDNS(cmd string, family Family, proxyGroupName, dnsGroupName string) {
	sh := shell.Bind(
		chainNames,
		shell.WithValues(
			`cmd`, cmd,
			`proxyGroupName`, proxyGroupName,
			`dnsGroupName`, dnsGroupName,
			`addr`, utils.IIF(family == IPv4, `127.0.0.1`, `::1`),
			`port`, DNSPort,
		),
	)

	sh.Run(`${cmd} -t nat -A ${output} -p tcp -m tcp --dport 53 --syn -m owner ! --gid-owner ${proxyGroupName} -m owner ! --gid-owner ${dnsGroupName} -j REDIRECT --to-ports ${port}`)
	sh.Run(`${cmd} -t nat -A ${output} -p udp -m udp --dport 53 -m conntrack --ctstate NEW -m owner ! --gid-owner ${proxyGroupName} -m owner ! --gid-owner ${dnsGroupName} -j REDIRECT --to-ports ${port}`)

	sh.Run(`${cmd} -t nat -A ${postrouting} -d ${addr} ! -s ${addr} -j SNAT --to-source ${addr}`)

	sh.Run(`${cmd} -t nat -A ${prerouting} -p tcp -m tcp --dport 53 --syn -m addrtype ! --src-type LOCAL -j REDIRECT --to-ports ${port}`)
	sh.Run(`${cmd} -t nat -A ${prerouting} -p udp -m udp --dport 53 -m conntrack --ctstate NEW -m addrtype ! --src-type LOCAL -j REDIRECT --to-ports ${port}`)
}

const (
	TPROXY_SERVER_IP_4 = `127.0.0.1`
	TPROXY_SERVER_IP_6 = `::1`
	TPROXY_SERVER_PORT = `60080`

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

func TProxy(cmd string, family Family, tcp, udp bool, proxyGroupName, dnsGroupName string) {
	sh := shell.Bind(
		shell.WithValues(`cmd`, cmd, `table`, `mangle`,
			`blackSetName`, utils.IIF(family == IPv4, BLACK_SET_NAME_4, BLACK_SET_NAME_6),
			`whiteSetName`, utils.IIF(family == IPv4, WHITE_SET_NAME_4, WHITE_SET_NAME_6),
		),
		chainNames,
		tproxyValues,
		shell.WithValues(
			`proxyGroupName`, proxyGroupName,
			`dnsGroupName`, dnsGroupName,
		),
	)

	sh.Run(`${cmd} -t ${table} -A ${rule} -m set --match-set ${whiteSetName} dst -m set ! --match-set ${blackSetName} dst -j RETURN`)
	sh.Run(`${cmd} -t ${table} -A ${rule} -j CONNMARK --set-mark ${TPROXY_MARK}`)

	sh.Run(`${cmd} -t mangle -A ${output} -m addrtype --dst-type LOCAL -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${output} -m conntrack --ctdir REPLY -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${output} -m owner --gid-owner ${proxyGroupName} -j RETURN`)

	if tcp {
		sh.Run(`${cmd} -t mangle -A ${output} -p tcp -m tcp --dport 53 -m owner ! --gid-owner ${dnsGroupName} -j RETURN`)
	}
	if udp {
		sh.Run(`${cmd} -t mangle -A ${output} -p udp -m udp --dport 53 -m owner ! --gid-owner ${dnsGroupName} -j RETURN`)
	}

	if tcp {
		sh.Run(`${cmd} -t mangle -A ${output} -p tcp -m tcp --syn -j ${rule}`)
	}
	if udp {
		sh.Run(`${cmd} -t mangle -A ${output} -p udp -m conntrack --ctstate NEW,RELATED -j ${rule}`)
	}

	sh.Run(`${cmd} -t mangle -A ${output} -m connmark --mark ${TPROXY_MARK} -j MARK --set-mark ${TPROXY_MARK}`)

	sh.Run(`${cmd} -t mangle -A ${prerouting} -m addrtype --dst-type LOCAL -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${prerouting} -m conntrack --ctdir REPLY -j RETURN`)

	if tcp {
		sh.Run(`${cmd} -t mangle -A ${prerouting} -p tcp -m tcp --syn ! --dport 53 -m addrtype ! --src-type LOCAL -j ${rule}`)
	}

	if udp {
		sh.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m udp ! --dport 53 -m conntrack --ctstate NEW,RELATED -m addrtype ! --src-type LOCAL -j ${rule}`)
	}

	if tcp {
		values := shell.WithValues(`ip`, utils.IIF(family == 4, TPROXY_SERVER_IP_4, TPROXY_SERVER_IP_6), `port`, TPROXY_SERVER_PORT)
		sh.Run(`${cmd} -t mangle -A ${prerouting} -p tcp -m connmark --mark ${TPROXY_MARK} -j TPROXY --on-ip ${ip} --on-port ${port} --tproxy-mark ${TPROXY_MARK}`, values)
	}
	if udp {
		values := shell.WithValues(`ip`, utils.IIF(family == 4, TPROXY_SERVER_IP_4, TPROXY_SERVER_IP_6), `port`, TPROXY_SERVER_PORT)
		sh.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m connmark --mark ${TPROXY_MARK} -j TPROXY --on-ip ${ip} --on-port ${port} --tproxy-mark ${TPROXY_MARK}`, values)
	}
}

func DropQUIC(cmd string, family Family, proxyGroupName, dnsGroupName string) {
	sh := shell.Bind(
		chainNames,
		shell.WithValues(`cmd`, cmd,
			`blackSetName`, utils.IIF(family == 4, BLACK_SET_NAME_4, BLACK_SET_NAME_6),
			`whiteSetName`, utils.IIF(family == 4, WHITE_SET_NAME_4, WHITE_SET_NAME_6),
			`proxyGroupName`, proxyGroupName,
		),
	)

	sh.Run(`${cmd} -t mangle -A ${quic} -m set --match-set ${whiteSetName} dst -m set ! --match-set ${blackSetName} dst -j RETURN`)
	sh.Run(`${cmd} -t mangle -A ${quic} -j DROP`)

	sh.Run(`${cmd} -t mangle -A ${output} -p udp -m udp --dport 443 -m conntrack --ctdir ORIGINAL -m addrtype ! --dst-type LOCAL -m owner ! --gid-owner ${proxyGroupName} -j ${quic}`)
	sh.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m udp --dport 443 -m conntrack --ctdir ORIGINAL -m addrtype ! --dst-type LOCAL -j ${quic}`)
}
