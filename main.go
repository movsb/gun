package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func SetKernelParams(ctx context.Context, v4, v6 bool) {
	sysctlAllInterfaces := func(family int, kv string) {
		paths := utils.Must1(filepath.Glob(fmt.Sprintf(`/proc/sys/net/ipv%d/conf/*`, family)))
		for _, path := range paths {
			conf := strings.TrimPrefix(path, `/proc/sys/`)
			utils.MustRun(`sysctl`, `-w`, fmt.Sprintf(`%s/%s`, conf, kv))
		}
	}

	if v4 {
		utils.MustRun(`sysctl`, `-w`, `net.ipv4.ip_forward=1`)
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
		utils.MustRunContext(ctx, `chinadns-ng`, args...)
		log.Println(`exit chinadns`)
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
		f := `inet`
		if family == 6 {
			f += `6`
		}
		utils.MustRun(`ipset`, `create`, name, `hash:net`, `family`, f)

		cmd := make([]string, 0, len(ips))
		for _, ip := range ips {
			cmd = append(cmd, fmt.Sprintf(`add %s %s`, name, ip))
		}
		ecmd := exec.Command(`ipset`, `-!`, `restore`)
		ecmd.Stdin = strings.NewReader(strings.Join(cmd, "\n"))
		ecmd.Stdout = os.Stdout
		ecmd.Stderr = os.Stderr
		utils.Must(ecmd.Run())
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
		InitIPSet(`gun_white4`, 4, ips)

		ips = append([]string{}, ignListExtFile.IPv6...)
		ips = append(ips, whiteFile.IPv6...)
		InitIPSet(`gun_white6`, 6, ips)
	case GfwMode:
		ips := append([]string{}, gfwListExtFile.IPv4...)
		ips = append(ips, blackFile.IPv4...)
		InitIPSet(`gun_black4`, 4, ips)

		ips = append([]string{}, gfwListExtFile.IPv6...)
		ips = append(ips, blackFile.IPv6...)
		InitIPSet(`gun_black6`, 6, ips)
	case ChinaRoute:
		ips := append([]string{}, ignListExtFile.IPv4...)
		ips = append(ips, whiteFile.IPv4...)
		ips = append(ips, chnroute4TxtFile.IPv4...)
		InitIPSet(`gun_white4`, 4, ips)

		ips = append([]string{}, ignListExtFile.IPv6...)
		ips = append(ips, whiteFile.IPv6...)
		ips = append(ips, chnroute6TxtFile.IPv6...)
		InitIPSet(`gun_white6`, 6, ips)

		ips = append([]string{}, gfwListExtFile.IPv4...)
		ips = append(ips, blackFile.IPv4...)
		InitIPSet(`gun_black4`, 4, ips)

		ips = append([]string{}, gfwListExtFile.IPv6...)
		ips = append(ips, blackFile.IPv6...)
		InitIPSet(`gun_black6`, 6, ips)
	}
}

func FlushIPSet() {
	output := utils.CmdOutput(`ipset`, `-n`, `list`)
	parts := strings.Split(output, "\n")
	for _, p := range parts {
		if !strings.HasPrefix(p, `gun_`) {
			continue
		}
		if err := utils.Run(`ipset`, `destroy`, p); err != nil {
			log.Println(err)
		}
	}
}

func StartIPRoute(family int) {
	f := fmt.Sprintf(`-%d`, family)
	utils.MustRun(`ip`, f, `route`, `add`, `local`, `default`, `dev`, `lo`, `table`, `233`)

	// output := utils.CmdOutput(`ip`, `rule`, `help`)
	args := []string{f, `rule`, `add`, `fwmark`, `0x2333`, `table`, `233`}
	// args = append(args, `protocol`, `static`)
	utils.MustRun(`ip`, args...)
}

func FlushIPRoute(family int) {
	f := fmt.Sprintf(`-%d`, family)
	utils.Run(`ip`, f, `rule`, `del`, `table`, `233`)
	// del or flush?
	utils.Run(`ip`, f, `route`, `del`, `table`, `233`)
}

func StartIPTablesPre(cmd string) {
	utils.MustRun(cmd, `-t`, `mangle`, `-N`, `GUN_PREROUTING`)
	utils.MustRun(cmd, `-t`, `mangle`, `-N`, `GUN_OUTPUT`)

	utils.MustRun(cmd, `-t`, `nat`, `-N`, `GUN_PREROUTING`)
	utils.MustRun(cmd, `-t`, `nat`, `-N`, `GUN_OUTPUT`)
	utils.MustRun(cmd, `-t`, `nat`, `-N`, `GUN_POSTROUTING`)
}

func StartIPTablesPost(cmd string) {
	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `PREROUTING`, `-j`, `GUN_PREROUTING`)
	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `OUTPUT`, `-j`, `GUN_OUTPUT`)

	utils.MustRun(cmd, `-t`, `nat`, `-A`, `PREROUTING`, `-j`, `GUN_PREROUTING`)
	utils.MustRun(cmd, `-t`, `nat`, `-A`, `OUTPUT`, `-j`, `GUN_OUTPUT`)
	utils.MustRun(cmd, `-t`, `nat`, `-A`, `POSTROUTING`, `-j`, `GUN_POSTROUTING`)
}

func CreateGunRules(mode Mode, cmd string, family int, typ string) {
	var addr string
	var whiteSetName, blackSetName string
	switch family {
	case 4:
		addr = `127.0.0.1:60080`
		whiteSetName = `gun_white4`
		blackSetName = `gun_black4`
	case 6:
		addr = `[::1]:60080`
		whiteSetName = `gun_white6`
		blackSetName = `gun_black6`
	}

	var table string
	var action []string
	switch typ {
	case `tproxy`:
		table = `mangle`
		action = []string{`-j`, `CONNMARK`, `--set-mark`, `0x2333`}
	default:
		table = `nat`
		action = []string{`-p`, `tcp`, `-j`, `DNAT`, `--to-destination`, addr}
	}

	args := []string{}
	args = append(args, `-t`, table, `-N`, `GUN_RULE`)
	utils.MustRun(cmd, args...)

	switch mode {
	case GlobalMode:
		args = []string{}
		args = append(args, `-t`, table, `-A`, `GUN_RULE`, `-m`, `set`, `!`, `--match-set`, whiteSetName, `dst`)
		args = append(args, action...)
		utils.MustRun(cmd, args...)
	case GfwMode:
		args = []string{}
		args = append(args, `-t`, table, `-A`, `GUN_RULE`, `-m`, `set`, `--match-set`, blackSetName, `dst`)
		args = append(args, action...)
		utils.MustRun(cmd, args...)
	case ChinaRoute:
		args = []string{}
		args = append(args, `-t`, table, `-A`, `GUN_RULE`, `-m`, `set`, `--match-set`, whiteSetName, `dst`, `-m`, `set`, `!`, `--match-set`, blackSetName, `dst`, `-j`, `RETURN`)
		utils.MustRun(cmd, args...)
		args = []string{}
		args = append(args, `-t`, table, `-A`, `GUN_RULE`)
		utils.MustRun(cmd, args...)
	}
}

func DoProxyTProxy(mode Mode, cmd string, family int, tcp, udp bool, proxyGroupName, dnsGroupName string) {
	CreateGunRules(mode, cmd, family, `tproxy`)

	var addr string
	switch family {
	case 4:
		addr = `127.0.0.1`
	case 6:
		addr = `::1`
	}

	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-m`, `addrtype`, `--dst-type`, `LOCAL`, `-j`, `RETURN`)
	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-m`, `conntrack`, `--ctdir`, `REPLY`, `-j`, `RETURN`)
	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-m`, `owner`, `--gid-owner`, proxyGroupName, `-j`, `RETURN`)

	if tcp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-p`, `tcp`, `-m`, `tcp`, `--dport`, `53`, `-m`, `owner`, `!`, `--gid-owner`, dnsGroupName, `-j`, `RETURN`)
	}
	if udp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-p`, `udp`, `-m`, `udp`, `--dport`, `53`, `-m`, `owner`, `!`, `--gid-owner`, dnsGroupName, `-j`, `RETURN`)
	}

	if tcp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-p`, `tcp`, `-m`, `tcp`, `--syn`, `-j`, `GUN_RULE`)
	}
	if udp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-p`, `udp`, `-m`, `conntrack`, `--ctstate`, `NEW,RELATED`, `-j`, `GUN_RULE`)
	}

	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-m`, `connmark`, `--mark`, `0x2333`, `-j`, `MARK`, `--set-mark`, `0x2333`)

	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-m`, `addrtype`, `--dst-type`, `LOCAL`, `-j`, `MARK`, `--set-mark`, `0x2333`)
	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-m`, `conntrack`, `--ctdir`, `REPLY`, `-j`, `RETURN`)

	if tcp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-p`, `tcp`, `-m`, `tcp`, `--syn`, `!`, `--dport`, `53`, `-m`, `addrtype`, `!`, `--src-type`, `LOCAL`, `-j`, `GUN_RULE`)
	}

	if udp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-p`, `udp`, `-m`, `udp`, `!`, `--dport`, `53`, `-m`, `conntrack`, `--ctstate`, `NEW,RELATED`, `-m`, `addrtype`, `!`, `--src-type`, `LOCAL`, `-j`, `GUN_RULE`)
	}

	if tcp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-p`, `tcp`, `-m`, `connmark`, `--mark`, `0x2333`, `-j`, `TPROXY`, `--on-ip`, addr, `--on-port`, `60080`, `--tproxy-mark`, `0x2333`)
	}
	if udp {
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-p`, `udp`, `-m`, `connmark`, `--mark`, `0x2333`, `-j`, `TPROXY`, `--on-ip`, addr, `--on-port`, `60080`, `--tproxy-mark`, `0x2333`)
	}
}

func DoProxyDNAT(mode Mode, cmd string, family int, proxyGroupName string) {
	CreateGunRules(mode, cmd, family, `dnat`)

	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_OUTPUT`, `-p`, `tcp`, `-m`, `tcp`, `--syn`, `-m`, `addrtype`, `-!`, `--dst-type`, `LOCAL`, `-m`, `owner`, `!`, `--gid-owner`, proxyGroupName, `-j`, `GUN_RULE`)

	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_PREROUTING`, `-p`, `tcp`, `-m`, `tcp`, `--syn`, `-m`, `addrtype`, `-!`, `--src-type`, `LOCAL`, `!`, `--dst-type`, `LOCAL`, `-j`, `GUN_RULE`)
}

func DropQUIC(mode Mode, cmd string, family int, proxyGroupName string) {
	utils.MustRun(cmd, `-t`, `mangle`, `-N`, `GUN_QUIC`)

	var whiteSetName, blackSetName string
	switch family {
	case 4:
		whiteSetName = `gun_white4`
		blackSetName = `gun_black4`
	case 6:
		whiteSetName = `gun_white6`
		blackSetName = `gun_black6`
	}

	switch mode {
	case GlobalMode:
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_QUIC`, `-m`, `set`, `!`, `--match-set`, whiteSetName, `dst`, `-j`, `DROP`)
	case GfwMode:
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_QUIC`, `-m`, `set`, `--match-set`, blackSetName, `dst`, `-j`, `DROP`)
	case ChinaRoute:
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_QUIC`, `-m`, `set`, `--match-set`, whiteSetName, `dst`, `-m`, `set`, `!`, `--match-set`, blackSetName, `dst`, `-j`, `RETURN`)
		utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_QUIC`, `-j`, `DROP`)
	}

	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_OUTPUT`, `-p`, `udp`, `-m`, `udp`, `--dport`, `443`, `-m`, `conntrack`, `--ctdir`, `ORIGINAL`, `-m`, `addrtype`, `!`, `--dst-type`, `LOCAL`, `-m`, `owner`, `!`, `--gid-owner`, proxyGroupName, `-j`, `GUN_QUIC`)

	utils.MustRun(cmd, `-t`, `mangle`, `-A`, `GUN_PREROUTING`, `-p`, `udp`, `-m`, `udp`, `--dport`, `443`, `-m`, `conntrack`, `--ctdir`, `ORIGINAL`, `-m`, `addrtype`, `!`, `--dst-type`, `LOCAL`, `-j`, `GUN_QUIC`)
}

func FlushIPTables() {
	flush := func(cmd string) {
		utils.Run(cmd, `-t`, `mangle`, `-D`, `PREROUTING`, `-j`, `GUN_PREROUTING`)
		utils.Run(cmd, `-t`, `mangle`, `-D`, `OUTPUT`, `-j`, `GUN_OUTPUT`)

		utils.Run(cmd, `-t`, `nat`, `-D`, `PREROUTING`, `-j`, `GUN_PREROUTING`)
		utils.Run(cmd, `-t`, `nat`, `-D`, `OUTPUT`, `-j`, `GUN_OUTPUT`)
		utils.Run(cmd, `-t`, `nat`, `-D`, `POSTROUTING`, `-j`, `GUN_POSTROUTING`)

		for _, table := range []string{`mangle`, `nat`} {
			output := utils.CmdOutput(cmd, `-t`, table, `-S`)
			parts := strings.Split(output, "\n")
			for _, p := range parts {
				if !strings.HasPrefix(p, `-N GUN_`) {
					continue
				}
				name := strings.Fields(p)[1]
				utils.MustRun(cmd, `-t`, table, `-F`, name)
				utils.MustRun(cmd, `-t`, table, `-X`, name)
			}
		}
	}

	flush(`iptables-legacy`)
	flush(`ip6tables-legacy`)
}

func RedirectDNSRequests(cmd string, family int, proxyGroupName, dnsGroupName string) {
	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_OUTPUT`, `-p`, `tcp`, `-m`, `tcp`, `--dport`, `53`, `--syn`, `-m`, `owner`, `!`, `--gid-owner`, proxyGroupName, `-m`, `owner`, `!`, `--gid-owner`, dnsGroupName, `-j`, `REDIRECT`, `--to-ports`, `60053`)
	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_OUTPUT`, `-p`, `udp`, `-m`, `udp`, `--dport`, `53`, `-m`, `conntrack`, `--ctstate`, `NEW`, `-m`, `owner`, `!`, `--gid-owner`, proxyGroupName, `-m`, `owner`, `!`, `--gid-owner`, dnsGroupName, `-j`, `REDIRECT`, `--to-ports`, `60053`)

	var addr string
	switch family {
	case 4:
		addr = `127.0.0.1`
	case 6:
		addr = `::1`
	}
	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_POSTROUTING`, `-d`, addr, `!`, `-s`, addr, `-j`, `SNAT`, `--to-source`, addr)

	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_PREROUTING`, `-p`, `tcp`, `-m`, `tcp`, `--dport`, `53`, `--syn`, `-m`, `addrtype`, `!`, `--src-type`, `LOCAL`, `-j`, `REDIRECT`, `--to-ports`, `60053`)
	utils.MustRun(cmd, `-t`, `nat`, `-A`, `GUN_PREROUTING`, `-p`, `udp`, `-m`, `udp`, `--dport`, `53`, `-m`, `conntrack`, `--ctstate`, `NEW`, `-m`, `addrtype`, `!`, `--src-type`, `LOCAL`, `-j`, `REDIRECT`, `--to-ports`, `60053`)
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
	FlushIPTables()
	SetKernelParams(context.Background(), true, true)
	StartIPSet(ChinaRoute, []string{`223.5.5.5`}, []string{`240C::6666`}, []string{`8.8.8.8`}, []string{`2001:4860:4860::8888`})
	StartChinaDNS(ctx, ChinaRoute, true, true, false, `always`, nil)
	StartIPRoute(4)
	StartIPRoute(6)
	StartIPTables(ChinaRoute, `proxy`, `proxy_dns`)
}

func Stop() {
	FlushIPTables()
	FlushIPRoute(4)
	FlushIPRoute(6)
	FlushIPSet()
}

// opkg install iptables-legacy ip6tables-legacy ipset kmod-ipt-conntrack iptables-mod-extra(for addrtype)
// kmod-ipt-nat kmod-ipt-nat6 ip6tables-zz-legacy shadow-groupadd iptables-mod-conntrack-extra iptables-mod-tproxy

func main() {
	rootCmd := &cobra.Command{
		Use:   os.Args[0],
		Short: `gun <command>`,
	}
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
