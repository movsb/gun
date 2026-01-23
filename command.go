package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/movsb/gun/dns"
	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/spf13/cobra"
)

func cmdUpdate(cmd *cobra.Command, args []string) {
	update(cmd.Context())
}

func update(ctx context.Context) {
	fmt.Println(`正在尝试更新所有的规则配置文件...`)
	time.Sleep(time.Millisecond * 500)

	fmt.Println(`正在更新中国域名列表...`)
	rules.UpdateChinaDomains(ctx)

	fmt.Println(`正在更新被墙域名列表...`)
	rules.UpdateGFWDomains(ctx)

	fmt.Println(`正在更新中国路由列表...`)
	rules.UpdateChinaRoutes(ctx)

	if !utils.FileExists(rules.BannedUserTxt) {
		fmt.Println(`写入被墙的额外列表...`)
		utils.Must(os.WriteFile(rules.BannedUserTxt, rules.BannedDefaultText, 0644))
	}
	if !utils.FileExists(rules.IgnoredUserTxt) {
		fmt.Println(`写入直连的额外列表...`)
		utils.Must(os.WriteFile(rules.IgnoredUserTxt, rules.IgnoredDefaultText, 0644))
	}
}

func cmdStart(cmd *cobra.Command, args []string) {
	defer func() {
		log.Println(`还原系统状态...`)
		stop()
		log.Println(`已还原系统状态。`)
	}()

	// 等待HTTP服务器结束或进程被kill（因为context结束）。
	defer time.Sleep(time.Second)

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	exited := make(chan error)

	start(ctx, exited)

	go serve(ctx)

	time.Sleep(time.Second)
	log.Println(`一切就绪。`)

	select {
	case <-ctx.Done():
	case err := <-exited:
		log.Println(err)
	}
}

func start(ctx context.Context, exited chan<- error) {
	var (
		dnsLocals       = []string{`223.5.5.5`, `240c::6666`}
		dnsRemotes      = []string{`8.8.8.8`, `2001:4860:4860::8888`}
		proxyGroupName  = `gun_proxy`
		directGroupName = `gun_direct`
	)

	log.Println(`加载数据、检查系统状态...`)
	states := targets.LoadStates(directGroupName, proxyGroupName)

	states.AddBannedIPs(dnsRemotes)
	states.AddIgnoredIPs(dnsLocals)

	log.Println(`设置内核参数...`)
	tables.SetKernelParams(true, true)

	log.Println(`创建表和链...`)
	tables.CreateChains(states.Ip4tables)
	tables.CreateChains(states.Ip6tables)

	log.Println(`创建黑白IP列表集...`)
	tables.CreateIPSet(states.White4(), states.Black4(), states.White6(), states.Black6())

	log.Println(`添加系统路由...`)
	tables.CreateIPRoute(tables.IPv4)
	tables.CreateIPRoute(tables.IPv6)

	log.Println(`丢弃QUIC请求...`)
	tables.DropQUIC(states.Ip4tables, tables.IPv4, proxyGroupName, directGroupName)
	tables.DropQUIC(states.Ip6tables, tables.IPv6, proxyGroupName, directGroupName)

	log.Println(`转发DNS请求...`)
	tables.ProxyDNS(states.Ip4tables, tables.IPv4, proxyGroupName, directGroupName)
	tables.ProxyDNS(states.Ip6tables, tables.IPv6, proxyGroupName, directGroupName)

	log.Println(`转发TCP/UDP到TPROXY...`)
	tables.TProxy(states.Ip4tables, tables.IPv4, true, true, proxyGroupName, directGroupName)
	tables.TProxy(states.Ip6tables, tables.IPv6, true, true, proxyGroupName, directGroupName)

	// TODO: 没有删除。
	// chinaDomainsFile := states.ChinaDomainsFile()
	// bannedDomainsFile := states.BannedDomainsFile()

	log.Println(`启动DNS进程...`)
	chinaRoutes := []string{}
	chinaRoutes = append(chinaRoutes, states.White4()...)
	chinaRoutes = append(chinaRoutes, states.White6()...)
	os.WriteFile(`/tmp/routes.txt`, []byte(strings.Join(chinaRoutes, "\n")), 0644)

	go shell.Run(
		`./gun dns server --china-upstream 223.5.5.5 --banned-upstream 8.8.8.8 --china-domains-file ${china_domains_file} --banned-domains-file ${banned_domains_file} --china-routes-file ${china_routes_file} --white-set-4 ${whiteSet4} --black-set-4 ${blackSet4}`,
		shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr), shell.WithGID(states.DirectGroupID),
		shell.WithValues(
			`china_domains_file`, states.ChinaDomainsFile(),
			`banned_domains_file`, states.BannedDomainsFile(),
			`china_routes_file`, `/tmp/routes.txt`,
			`whiteSet4`, tables.WHITE_SET_NAME_4,
			`blackSet4`, tables.BLACK_SET_NAME_4,
		),
	)

	go shell.Run(`ipt2socks`, shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))

	go shell.Run(`http2socks client -s https://alt.twofei.com/xxx/ -t xxx`, shell.WithGID(states.ProxyGroupID), shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr))
}

func cmdStop(cmd *cobra.Command, args []string) {
	stop()
}

func stop() {
	ip4, ip6 := targets.FindIPTablesCommands()
	tables.DeleteChains(ip4)
	tables.DeleteChains(ip6)
	tables.DeleteIPRoute(tables.IPv4)
	tables.DeleteIPRoute(tables.IPv6)
	tables.DeleteIPSet()
}

func serve(ctx context.Context) {
	s := http.Server{
		Addr: `0.0.0.0:3486`,
	}

	go func() {
		<-ctx.Done()
		log.Println(`正在结束HTTP服务器...`)
		s.Shutdown(context.Background())
		log.Println(`已经结束HTTP服务器。`)
	}()

	log.Println(`运行HTTP服务器...`)
	if err := s.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

func cmdExec(cmd *cobra.Command, args []string) {
	group := targets.GetGroupID(args[0])
	args = args[1:]
	shell.Run(args[0], shell.WithArgs(args[1:]...), shell.WithGID(group), shell.WithSilent(),
		shell.WithStdin(os.Stdin), shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
	)
}

func cmdDNSServer(cmd *cobra.Command, args []string) {
	port := utils.Must1(cmd.Flags().GetUint16(`port`))
	chinaUpstream := utils.Must1(cmd.Flags().GetString(`china-upstream`))
	bannedUpstream := utils.Must1(cmd.Flags().GetString(`banned-upstream`))
	chinaDomainsFile := utils.Must1(cmd.Flags().GetString(`china-domains-file`))
	bannedDomainsFile := utils.Must1(cmd.Flags().GetString(`banned-domains-file`))
	chinaRoutesFile := utils.Must1(cmd.Flags().GetString(`china-routes-file`))
	whiteSet4 := utils.Must1(cmd.Flags().GetString(`white-set-4`))
	blackSet4 := utils.Must1(cmd.Flags().GetString(`black-set-4`))

	chinaDomains := strings.Split(string(utils.Must1(os.ReadFile(chinaDomainsFile))), "\n")
	bannedDomains := strings.Split(string(utils.Must1(os.ReadFile(bannedDomainsFile))), "\n")
	chinaRoutes := strings.Split(string(utils.Must1(os.ReadFile(chinaRoutesFile))), "\n")

	chinaRoutesIPs := []netip.Prefix{}
	for _, r := range chinaRoutes {
		if strings.IndexByte(r, '/') < 0 {
			if strings.IndexByte(r, ':') >= 0 {
				r += `/128`
			} else {
				r += `/32`
			}
		}
		chinaRoutesIPs = append(chinaRoutesIPs, netip.MustParsePrefix(r))
	}

	s := dns.NewServer(int(port),
		chinaUpstream, bannedUpstream,
		chinaDomains, bannedDomains,
		chinaRoutesIPs,
		whiteSet4, blackSet4,
	)

	utils.Must(s.ListenAndServe())
}
