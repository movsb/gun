package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func SetKernelParams(ctx context.Context, v4, v6 bool) {
	sysctlAllInterfaces := func(family int, kv string) {
		paths := utils.Must1(filepath.Glob(fmt.Sprintf(`/proc/sys/net/ipv%d/conf/*`, family)))
		for _, path := range paths {
			conf := strings.TrimPrefix(path, `/proc/sys/`)
			shell.Run(`sysctl -wq ${conf}/${kv}`, shell.WithValues(`conf`, conf, `kv`, kv))
		}
	}

	if v4 {
		shell.Run(`sysctl -wq net.ipv4.ip_forward=1`)
	}
	if v6 {
		sysctlAllInterfaces(6, `forwarding=1`)
	}

	sysctlAllInterfaces(4, `route_localnet=1`)
	sysctlAllInterfaces(4, `send_redirects=0`)
}

type Mode byte

const (
	GlobalMode Mode = iota + 1
	GfwMode
	ChinaRoute
)

func StartChinaDNS(ctx context.Context, mode Mode, v4, v6 bool, tcpOnly bool, dnsRemoteTCP string, extraOptions []string) {
	var args []string

	if v6 {
		args = append(args, `-b`, `::`)
	} else {
		args = append(args, `-b`, `0.0.0.0`)
	}

	args = append(args, `-l`, `60053`)

	getUpstream := func(direct bool, servers ...string) []string {
		opt := ``
		useTCP := false

		if direct {
			opt = `-c`
			useTCP = false
		} else {
			opt = `-t`
			switch dnsRemoteTCP {
			case `tcponly`:
				useTCP = tcpOnly
			case `always`:
				useTCP = true
			default:
				useTCP = false
			}
		}

		args := []string{}

		for _, s := range servers {
			if useTCP && !strings.Contains(s, `://`) {
				s = `tcp://` + s
			}
			args = append(args, opt, s)
		}

		return args
	}

	if v4 {
		args = append(args, getUpstream(true, `223.5.5.5`)...)
	}
	if v6 {
		args = append(args, getUpstream(true, `240c::6666`)...)
	}
	if v4 {
		args = append(args, getUpstream(false, `8.8.8.8`)...)
	}
	if v6 {
		args = append(args, getUpstream(false, `2001:4860:4860::8888`)...)
	}

	args = append(args, `--cache`, `4096`)
	args = append(args, `--cache-stale`, `65535`)
	args = append(args, `--cache-refresh`, `20`)
	args = append(args, `--verdict-cache`, `4096`)
	args = append(args, `--cache-db`, `dns-cache.db`)
	args = append(args, `--verdict-cache-db`, `verdict-cache.db`)
	args = append(args, extraOptions...)

	ignListExtFile := parseFile(`ignlist.ext`)
	gfwListExtFile := parseFile(`gfwlist.ext`)

	filesToRemove := []string{}

	switch mode {
	case GlobalMode:
		f1 := ignListExtFile.DomainFile()
		filesToRemove = append(filesToRemove, f1)
		args = append(args, `-m`, f1)
		args = append(args, `-d`, `gfw`)
		args = append(args, `-a`, `gun_white4,gun_white6`)
	case GfwMode:
		f1 := gfwListExtFile.DomainFile()
		filesToRemove = append(filesToRemove, f1)
		args = append(args, `-g`, fmt.Sprintf(`gfwlist.txt,%s`, f1))
		args = append(args, `-d`, `chn`)
		args = append(args, `-A`, `gun_black4,gun_black6`)
	case ChinaRoute:
		f1 := ignListExtFile.DomainFile()
		f2 := gfwListExtFile.DomainFile()
		filesToRemove = append(filesToRemove, f1, f2)
		args = append(args, `-m`, fmt.Sprintf(`chnlist.txt,%s`, f1))
		args = append(args, `-g`, fmt.Sprintf(`gfwlist.txt,%s`, f2))
		args = append(args, `-a`, `gun_white4,gun_white6`)
		args = append(args, `-A`, `gun_black4,gun_black6`)
		args = append(args, `-4`, `gun_white4`, `-6`, `gun_white6`)
	default:
		panic(`unknown mode`)
	}

	go func() {
		defer func() {
			for _, f := range filesToRemove {
				os.Remove(f)
			}
		}()
		defer log.Println(`exit chinadns`)
		shell.Run(`chinadns-ng`, shell.WithContext(ctx), shell.WithArgs(args...))
	}()

	time.Sleep(time.Second)
}

type File struct {
	IPv4    []string
	IPv6    []string
	Domains []string
}

func (f *File) Merge(from *File) {
	f.IPv4 = append(f.IPv4, from.IPv4...)
	f.IPv6 = append(f.IPv6, from.IPv6...)
	f.Domains = append(f.Domains, from.Domains...)
}

func (f *File) IPv4File() string {
	return f.saveTmpFile(f.IPv4)
}
func (f *File) IPv6File() string {
	return f.saveTmpFile(f.IPv6)
}
func (f *File) DomainFile() string {
	return f.saveTmpFile(f.Domains)
}
func (f *File) saveTmpFile(list []string) string {
	tf := utils.Must1(os.CreateTemp(``, ``))
	utils.Must1(tf.WriteString(strings.Join(list, "\n")))
	utils.Must(tf.Close())
	return tf.Name()
}

func parseFile(name string) *File {
	f := &File{}
	fp := utils.Must1(os.Open(name))
	defer fp.Close()
	scn := bufio.NewScanner(fp)
	for scn.Scan() {
		t := scn.Text()
		switch {
		case strings.HasPrefix(t, `@`):
			f.Domains = append(f.Domains, t[1:])
		case strings.HasPrefix(t, `-`):
			f.IPv4 = append(f.IPv4, t[1:])
		case strings.HasPrefix(t, `~`):
			f.IPv6 = append(f.IPv6, t[1:])
		}
	}
	if scn.Err() != nil {
		panic(scn.Err())
	}
	return f
}

func StartIPSet(mode Mode, dnsDirect4, dnsDirect6, dnsRemote4, dnsRemote6 []string) {
	InitIPSet := func(name string, family int, ips []string) {
		values := shell.WithValues(
			`name`, name,
			`family`, utils.IIF(family == 4, `inet`, `inet6`),
		)
		shell.Run(`ipset create ${name} hash:net family ${family}`, values)

		buf := bytes.NewBuffer(nil)
		for _, ip := range ips {
			fmt.Fprintln(buf, `add`, name, ip)
		}
		shell.Run(`ipset -! restore`, shell.WithStdin(buf))
	}

	// # [proto://][host@]ip[#port][path] -> ip
	getUpstreamIP := func(s string) string {
		before, after, found := strings.Cut(s, `@`)
		if found {
			s = after
		}
		before, after, found = strings.Cut(s, `#`)
		if found {
			s = before
		}
		return s
	}

	ignListExtFile := parseFile(`ignlist.ext`)
	gfwListExtFile := parseFile(`gfwlist.ext`)
	chnroute4TxtFile := parseFile(`chnroute.txt`)
	chnroute6TxtFile := parseFile(`chnroute6.txt`)

	whiteFile := &File{
		IPv4: utils.Map(dnsDirect4, func(s string) string { return getUpstreamIP(s) }),
		IPv6: utils.Map(dnsDirect6, func(s string) string { return getUpstreamIP(s) }),
	}
	blackFile := &File{
		IPv4: utils.Map(dnsRemote4, func(s string) string { return getUpstreamIP(s) }),
		IPv6: utils.Map(dnsRemote6, func(s string) string { return getUpstreamIP(s) }),
	}

	switch mode {
	case GlobalMode:
		ips := append([]string{}, ignListExtFile.IPv4...)
		ips = append(ips, whiteFile.IPv4...)
		InitIPSet(WHITE_SET_NAME_4, 4, ips)

		ips = append([]string{}, ignListExtFile.IPv6...)
		ips = append(ips, whiteFile.IPv6...)
		InitIPSet(WHITE_SET_NAME_6, 6, ips)
	case GfwMode:
		ips := append([]string{}, gfwListExtFile.IPv4...)
		ips = append(ips, blackFile.IPv4...)
		InitIPSet(BLACK_SET_NAME_4, 4, ips)

		ips = append([]string{}, gfwListExtFile.IPv6...)
		ips = append(ips, blackFile.IPv6...)
		InitIPSet(BLACK_SET_NAME_6, 6, ips)
	case ChinaRoute:
		ips := append([]string{}, ignListExtFile.IPv4...)
		ips = append(ips, whiteFile.IPv4...)
		ips = append(ips, chnroute4TxtFile.IPv4...)
		InitIPSet(WHITE_SET_NAME_4, 4, ips)

		ips = append([]string{}, ignListExtFile.IPv6...)
		ips = append(ips, whiteFile.IPv6...)
		ips = append(ips, chnroute6TxtFile.IPv6...)
		InitIPSet(WHITE_SET_NAME_6, 6, ips)

		ips = append([]string{}, gfwListExtFile.IPv4...)
		ips = append(ips, blackFile.IPv4...)
		InitIPSet(BLACK_SET_NAME_4, 4, ips)

		ips = append([]string{}, gfwListExtFile.IPv6...)
		ips = append(ips, blackFile.IPv6...)
		InitIPSet(BLACK_SET_NAME_6, 6, ips)
	}
}

func FlushIPSet() {
	output := shell.Run(`ipset -n list`, shell.WithSilent())
	for p := range strings.SplitSeq(output, "\n") {
		if !strings.HasPrefix(p, `gun_`) {
			continue
		}
		shell.Run(`ipset destroy ${name}`, shell.WithValues(`name`, p))
	}
}

func StartIPRoute(family int) {
	values := shell.WithValues(`family`, family)
	shell.Run(`ip -${family} route add local default dev lo table 233`, values)
	shell.Run(`ip -${family} rule add fwmark 0x2333 table 233`, values)
}

var ignoreNotFound = shell.WithIgnoreErrors(`No such file or directory`, `No such process`)

func FlushIPRoute(family int) {
	values := shell.WithValues(`family`, family)
	shell.Run(`ip -${family} rule del table 233`, values, ignoreNotFound)
	// del or flush?
	shell.Run(`ip -${family} route del table 233`, values, ignoreNotFound)
}

const (
	GUN_PREFIX_     = `GUN_`
	GUN_PREROUTING  = `GUN_PREROUTING`
	GUN_OUTPUT      = `GUN_OUTPUT`
	GUN_POSTROUTING = `GUN_POSTROUTING`
	GUN_RULE        = `GUN_RULE`
	GUN_QUIC        = `GUN_QUIC`
)

var chainValues = shell.WithValues(`prerouting`, GUN_PREROUTING, `output`, GUN_OUTPUT, `postrouting`, GUN_POSTROUTING, `rule`, GUN_RULE, `quic`, GUN_QUIC)

func StartIPTablesPre(cmd string) {
	v := shell.WithValues(`cmd`, cmd)

	shell.Run(`${cmd} -t mangle -N ${prerouting}`, v, chainValues)
	shell.Run(`${cmd} -t mangle -N ${output}`, v, chainValues)

	shell.Run(`${cmd} -t nat -N ${prerouting}`, v, chainValues)
	shell.Run(`${cmd} -t nat -N ${output}`, v, chainValues)
	shell.Run(`${cmd} -t nat -N ${postrouting}`, v, chainValues)
}

func StartIPTablesPost(cmd string) {
	v := shell.WithValues(`cmd`, cmd)

	shell.Run(`${cmd} -t mangle -A PREROUTING -j ${prerouting}`, v, chainValues)
	shell.Run(`${cmd} -t mangle -A OUTPUT -j ${output}`, v, chainValues)

	shell.Run(`${cmd} -t nat -A PREROUTING -j ${prerouting}`, v, chainValues)
	shell.Run(`${cmd} -t nat -A OUTPUT -j ${output}`, v, chainValues)
	shell.Run(`${cmd} -t nat -A POSTROUTING -j ${postrouting}`, v, chainValues)
}

const (
	WHITE_SET_NAME_4 = `gun_white4`
	WHITE_SET_NAME_6 = `gun_white6`
	BLACK_SET_NAME_4 = `gun_black4`
	BLACK_SET_NAME_6 = `gun_black6`
)

const (
	TPROXY_SERVER_IP_4 = `127.0.0.1`
	TPROXY_SERVER_IP_6 = `::1`
	TPROXY_SERVER_PORT = `60080`
	TPROXY_MARK        = `0x2333`
)

var tproxyValues = shell.WithValues(
	`TPROXY_SERVER_IP_4`, TPROXY_SERVER_IP_4,
	`TPROXY_SERVER_IP_6`, TPROXY_SERVER_IP_6,
	`TPROXY_SERVER_PORT`, TPROXY_SERVER_PORT,
	`TPROXY_MARK`, `0x2333`,
)

func CreateGunRules(mode Mode, cmd string, family int, typ string) {
	var table string
	switch typ {
	case `tproxy`:
		table = `mangle`
	default:
		panic(`no dnat now`)
	}

	values := shell.WithValues(`cmd`, cmd, `table`, table,
		`blackSetName`, utils.IIF(family == 4, BLACK_SET_NAME_4, BLACK_SET_NAME_6),
		`whiteSetName`, utils.IIF(family == 4, WHITE_SET_NAME_4, WHITE_SET_NAME_6),
	)

	shell.Run(`${cmd} -t ${table} -N ${rule}`, values, chainValues)

	switch mode {
	case GlobalMode:
		shell.Run(`${cmd} -t ${table} -A ${rule} -m set ! --match-set ${whiteSetName} dst -j CONNMARK --set-mark ${TPROXY_MARK}`, values, chainValues, tproxyValues)
	case GfwMode:
		shell.Run(`${cmd} -t ${table} -A ${rule} -m set --match-set ${blackSetName} dst -j CONNMARK --set-mark ${TPROXY_MARK}`, values, chainValues, tproxyValues)
	case ChinaRoute:
		shell.Run(`${cmd} -t ${table} -A ${rule} -m set --match-set ${whiteSetName} dst -m set ! --match-set ${blackSetName} dst -j RETURN`, values, chainValues, tproxyValues)
		shell.Run(`${cmd} -t ${table} -A ${rule} -j CONNMARK --set-mark ${TPROXY_MARK}`, values, chainValues, tproxyValues)
	}
}

func DoProxyTProxy(mode Mode, cmd string, family int, tcp, udp bool, proxyGroupName, dnsGroupName string) {
	CreateGunRules(mode, cmd, family, `tproxy`)

	commonValues := shell.WithValues(`cmd`, cmd, `proxyGroupName`, proxyGroupName, `dnsGroupName`, dnsGroupName)

	shell.Run(`${cmd} -t mangle -A ${output} -m addrtype --dst-type LOCAL -j RETURN`, chainValues, commonValues)
	shell.Run(`${cmd} -t mangle -A ${output} -m conntrack --ctdir REPLY -j RETURN`, chainValues, commonValues)
	shell.Run(`${cmd} -t mangle -A ${output} -m owner --gid-owner ${proxyGroupName} -j RETURN`, chainValues, commonValues)

	if tcp {
		shell.Run(`${cmd} -t mangle -A ${output} -p tcp -m tcp --dport 53 -m owner ! --gid-owner ${dnsGroupName} -j RETURN`, chainValues, commonValues)
	}
	if udp {
		shell.Run(`${cmd} -t mangle -A ${output} -p udp -m udp --dport 53 -m owner ! --gid-owner ${dnsGroupName} -j RETURN`, chainValues, commonValues)
	}

	if tcp {
		shell.Run(`${cmd} -t mangle -A ${output} -p tcp -m tcp --syn -j ${rule}`, chainValues, commonValues)
	}
	if udp {
		shell.Run(`${cmd} -t mangle -A ${output} -p udp -m conntrack --ctstate NEW,RELATED -j ${rule}`, chainValues, commonValues)
	}

	shell.Run(`${cmd} -t mangle -A ${output} -m connmark --mark ${TPROXY_MARK} -j MARK --set-mark ${TPROXY_MARK}`, chainValues, commonValues, tproxyValues)

	shell.Run(`${cmd} -t mangle -A ${prerouting} -m addrtype --dst-type LOCAL -j RETURN`, chainValues, commonValues, tproxyValues)
	shell.Run(`${cmd} -t mangle -A ${prerouting} -m conntrack --ctdir REPLY -j RETURN`, chainValues, commonValues)

	if tcp {
		shell.Run(`${cmd} -t mangle -A ${prerouting} -p tcp -m tcp --syn ! --dport 53 -m addrtype ! --src-type LOCAL -j ${rule}`, chainValues, commonValues, tproxyValues)
	}

	if udp {
		shell.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m udp ! --dport 53 -m conntrack --ctstate NEW,RELATED -m addrtype ! --src-type LOCAL -j ${rule}`, chainValues, commonValues, tproxyValues)
	}

	if tcp {
		values := shell.WithValues(`ip`, utils.IIF(family == 4, TPROXY_SERVER_IP_4, TPROXY_SERVER_IP_6), `port`, TPROXY_SERVER_PORT)
		shell.Run(`${cmd} -t mangle -A ${prerouting} -p tcp -m connmark --mark ${TPROXY_MARK} -j TPROXY --on-ip ${ip} --on-port ${port} --tproxy-mark ${TPROXY_MARK}`, chainValues, commonValues, tproxyValues, values)
	}
	if udp {
		values := shell.WithValues(`ip`, utils.IIF(family == 4, TPROXY_SERVER_IP_4, TPROXY_SERVER_IP_6), `port`, TPROXY_SERVER_PORT)
		shell.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m connmark --mark ${TPROXY_MARK} -j TPROXY --on-ip ${ip} --on-port ${port} --tproxy-mark ${TPROXY_MARK}`, chainValues, commonValues, tproxyValues, values)
	}
}

func DropQUIC(mode Mode, cmd string, family int, proxyGroupName string) {
	commonValues := shell.WithValues(`cmd`, cmd,
		`blackSetName`, utils.IIF(family == 4, BLACK_SET_NAME_4, BLACK_SET_NAME_6),
		`whiteSetName`, utils.IIF(family == 4, WHITE_SET_NAME_4, WHITE_SET_NAME_6),
		`proxyGroupName`, proxyGroupName,
	)

	shell.Run(`${cmd} -t mangle -N ${quic}`, commonValues, chainValues)

	switch mode {
	case GlobalMode:
		shell.Run(`${cmd} -t mangle -A ${quic} -m set ! --match-set ${whiteSetName} dst -j DROP`, chainValues, commonValues)
	case GfwMode:
		shell.Run(`${cmd} -t mangle -A ${quic} -m set --match-set ${blackSetName} dst -j DROP`, chainValues, commonValues)
	case ChinaRoute:
		shell.Run(`${cmd} -t mangle -A ${quic} -m set --match-set ${whiteSetName} dst -m set ! --match-set ${blackSetName} dst -j RETURN`, chainValues, commonValues)
		shell.Run(`${cmd} -t mangle -A ${quic} -j DROP`, chainValues, commonValues)
	}

	shell.Run(`${cmd} -t mangle -A ${output} -p udp -m udp --dport 443 -m conntrack --ctdir ORIGINAL -m addrtype ! --dst-type LOCAL -m owner ! --gid-owner ${proxyGroupName} -j ${quic}`, chainValues, commonValues)
	shell.Run(`${cmd} -t mangle -A ${prerouting} -p udp -m udp --dport 443 -m conntrack --ctdir ORIGINAL -m addrtype ! --dst-type LOCAL -j ${quic}`, chainValues, commonValues)
}

// 清空所有相关的表和链。
//
// 会同时清空IPv4和IPv6，避免配置修改残留。
func flushIPTables() {
	ignoreNoChain := shell.WithIgnoreErrors(
		`Couldn't load target`,
		`No chain/target/match by that name`,
	)

	flush := func(cmd string) {
		commonValues := shell.WithValues(`cmd`, cmd)

		shell.Run(`${cmd} -t mangle -D PREROUTING -j ${prerouting}`, commonValues, chainValues, ignoreNoChain)
		shell.Run(`${cmd} -t mangle -D OUTPUT     -j ${output}`, commonValues, chainValues, ignoreNoChain)

		shell.Run(`${cmd} -t nat -D PREROUTING  -j ${prerouting}`, commonValues, chainValues, ignoreNoChain)
		shell.Run(`${cmd} -t nat -D OUTPUT      -j ${output}`, commonValues, chainValues, ignoreNoChain)
		shell.Run(`${cmd} -t nat -D POSTROUTING -j ${postrouting}`, commonValues, chainValues, ignoreNoChain)

		for _, table := range []string{`mangle`, `nat`} {
			output := shell.Run(`${cmd} -t ${table} -S`, commonValues, shell.WithValues(`table`, table), shell.WithSilent())
			for p := range strings.SplitSeq(output, "\n") {
				if !strings.HasPrefix(p, `-N `+GUN_PREFIX_) {
					continue
				}
				name := strings.Fields(p)[1]
				values := shell.WithValues(`cmd`, cmd, `table`, table, `name`, name)
				// 需要先清空再删除，否则会报错：iptables: Directory not empty.
				shell.Run(`${cmd} -t ${table} -F ${name}`, values)
				shell.Run(`${cmd} -t ${table} -X ${name}`, values)
			}
		}
	}

	flush(`iptables-legacy`)
	flush(`ip6tables-legacy`)
}

func RedirectDNSRequests(cmd string, family int, proxyGroupName, dnsGroupName string) {
	commonValues := shell.WithValues(`cmd`, cmd,
		`cmd`, cmd,
		`proxyGroupName`, proxyGroupName,
		`dnsGroupName`, dnsGroupName,
		`addr`, utils.IIF(family == 4, `127.0.0.1`, `::1`),
	)

	shell.Run(`${cmd} -t nat -A ${output} -p tcp -m tcp --dport 53 --syn -m owner ! --gid-owner ${proxyGroupName} -m owner ! --gid-owner ${dnsGroupName} -j REDIRECT --to-ports 60053`, commonValues, chainValues)
	shell.Run(`${cmd} -t nat -A ${output} -p udp -m udp --dport 53 -m conntrack --ctstate NEW -m owner ! --gid-owner ${proxyGroupName} -m owner ! --gid-owner ${dnsGroupName} -j REDIRECT --to-ports 60053`, commonValues, chainValues)

	shell.Run(`${cmd} -t nat -A ${postrouting} -d ${addr} ! -s ${addr} -j SNAT --to-source ${addr}`, commonValues, chainValues)

	shell.Run(`${cmd} -t nat -A ${prerouting} -p tcp -m tcp --dport 53 --syn -m addrtype ! --src-type LOCAL -j REDIRECT --to-ports 60053`, commonValues, chainValues)
	shell.Run(`${cmd} -t nat -A ${prerouting} -p udp -m udp --dport 53 -m conntrack --ctstate NEW -m addrtype ! --src-type LOCAL -j REDIRECT --to-ports 60053`, commonValues, chainValues)
}

func StartIPTables(mode Mode, proxyGroupName, dnsGroupName string) {
	_startIPTables := func(cmd string, family int) {
		StartIPTablesPre(cmd)

		DropQUIC(mode, cmd, family, proxyGroupName)

		RedirectDNSRequests(cmd, family, proxyGroupName, dnsGroupName)

		DoProxyTProxy(mode, cmd, family, true, true, proxyGroupName, dnsGroupName)

		// set snat rule

		StartIPTablesPost(cmd)
	}

	_startIPTables(`iptables-legacy`, 4)
	_startIPTables(`ip6tables-legacy`, 6)
}

func Start(ctx context.Context) {
	flushIPTables()
	SetKernelParams(context.Background(), true, true)
	StartIPSet(ChinaRoute, []string{`223.5.5.5`}, []string{`240C::6666`}, []string{`8.8.8.8`}, []string{`2001:4860:4860::8888`})
	StartChinaDNS(ctx, ChinaRoute, true, true, false, `always`, nil)
	StartIPRoute(4)
	StartIPRoute(6)
	StartIPTables(ChinaRoute, `proxy`, `proxy_dns`)
}

func Stop() {
	flushIPTables()
	FlushIPRoute(4)
	FlushIPRoute(6)
	FlushIPSet()
}

// opkg install iptables-legacy ip6tables-legacy ipset kmod-ipt-conntrack iptables-mod-extra(for addrtype)
// kmod-ipt-nat kmod-ipt-nat6 ip6tables-zz-legacy shadow-groupadd iptables-mod-conntrack-extra iptables-mod-tproxy

var verbose bool

func main() {
	rootCmd := &cobra.Command{
		Use:   os.Args[0],
		Short: `gun <command>`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			verbose = utils.Must1(cmd.Flags().GetBool(`verbose`))
		},
	}
	rootCmd.Flags().SortFlags = false
	rootCmd.Flags().BoolP(`verbose`, `v`, false, `是否输出更详细的日志。`)

	startCmd := &cobra.Command{
		Use: `start`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer log.Println(`canceling end `)
			defer time.Sleep(time.Second)
			defer cancel()
			defer log.Println(`canceling`)
			Start(ctx)
			select {}
		},
	}
	stopCmd := &cobra.Command{
		Use: `stop`,
		Run: func(cmd *cobra.Command, args []string) {
			Stop()
		},
	}
	rootCmd.AddCommand(startCmd, stopCmd)
	rootCmd.Execute()
}
