package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/movsb/gun/admin"
	"github.com/movsb/gun/dns"
	"github.com/movsb/gun/inputs/tproxy"
	"github.com/movsb/gun/outputs/socks5"
	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/movsb/gun/targets/alpine"
	"github.com/movsb/gun/targets/openwrt"
	"github.com/movsb/gun/targets/ubuntu"
	"github.com/movsb/http2socks"
	"github.com/spf13/cobra"
)

func mustBeRoot() {
	if os.Geteuid() != 0 {
		log.Fatalln(`需要以 root 用户身份运行此程序。`)
	}
}

func cmdUpdate(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()
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
	if !utils.FileExists(rules.BlockedUserTxt) {
		fmt.Println(`写入默认被屏蔽的域名列表...`)
		utils.Must(os.WriteFile(rules.BlockedUserTxt, rules.BlockedDefaultTxt, 0644))
	}
}

func cmdStart(cmd *cobra.Command, args []string) {
	mustBeRoot()
	targets.CheckCommands()

	// 启动之前总是清理一遍，防止上次启动的时候可能的没清理干净。
	stop()

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

	go httpServe(ctx)

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

	log.Println(`启动域名进程...`)
	// 启动DNS进程。
	// 需要在直连进程组。
	go shell.Run(`${self} tasks dns`,
		shell.WithCmdSelf(), shell.WithGID(states.DirectGroupID),
		shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
		shell.WithIgnoreErrors(`signal: interrupt`),
		shell.WithEnv(`PORT`, tables.DNSPort),
		shell.WithEnv(`CHINA_UPSTREAM`, `223.5.5.5`),
		shell.WithEnv(`BANNED_UPSTREAM`, `8.8.8.8`),
		shell.WithEnv(`CHINA_DOMAINS_FILE`, states.ChinaDomainsFile()),
		shell.WithEnv(`BANNED_DOMAINS_FILE`, states.BannedDomainsFile()),
		shell.WithEnv(`BLOCKED_DOMAINS_FILE`, states.BlockedDomainsFile()),
		shell.WithEnv(`CHINA_ROUTES_FILE`, states.ChinaRoutesFile()),
	)

	const http2socksAddr = `127.0.0.1:1080`

	log.Println(`启动接管进程...`)
	// 进程组无所谓。
	go shell.Run(`${self} tasks inputs tproxy`,
		shell.WithCmdSelf(),
		shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
		shell.WithIgnoreErrors(`signal: interrupt`),
		shell.WithEnv(`PORT`, tables.TPROXY_SERVER_PORT),
		shell.WithEnv(`SOCKS_SERVER`, http2socksAddr),
	)

	log.Println(`启动代理进程...`)
	// 需要在代理进程组。
	go shell.Run(`${self} tasks outputs http2socks`,
		shell.WithCmdSelf(), shell.WithGID(states.ProxyGroupID),
		shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
		shell.WithIgnoreErrors(`signal: interrupt`),
		shell.WithEnv(`SERVER`, utils.MustGetEnvString(`HTTP2SOCKS_SERVER`)),
		shell.WithEnv(`TOKEN`, utils.MustGetEnvString(`HTTP2SOCKS_TOKEN`)),
		shell.WithEnv(`LISTEN`, http2socksAddr),
	)
}

func cmdStop(cmd *cobra.Command, args []string) {
	mustBeRoot()
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

func httpServe(ctx context.Context) {
	h := admin.NewServer()

	s := http.Server{
		Addr:    `0.0.0.0:3486`,
		Handler: h.Handler(),
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
	mustBeRoot()
	group := targets.GetGroupID(args[0])
	args = args[1:]
	shell.Run(args[0], shell.WithArgs(args[1:]...), shell.WithGID(group), shell.WithSilent(),
		shell.WithStdin(os.Stdin), shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
	)
}

func cmdTasks(cmd *cobra.Command, args []string) {
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 10000, Max: 10000})

	if args[0] == `inputs` {
		if args[1] == `tproxy` {
			lis := utils.Must1(tproxy.ListenTCP(uint16(utils.MustGetEnvInt(`PORT`))))
			defer lis.Close()
			for {
				conn, err := lis.Accept()
				if err != nil {
					log.Fatalln(err)
				}
				// TPROXY接管后本地地址即是外部地址。
				remoteAddr := conn.LocalAddr().String()
				socksAddr := utils.MustGetEnvString(`SOCKS_SERVER`)
				go func() {
					if err := socks5.ProxyTCP4(conn, socksAddr, remoteAddr); err != nil {
						log.Println(err)
					}
				}()
			}
		}
	}

	if args[0] == `outputs` {
		if args[1] == `http2socks` {
			client := http2socks.NewClient(
				utils.MustGetEnvString(`SERVER`),
				utils.MustGetEnvString(`TOKEN`),
			)
			client.ListenAndServe(utils.MustGetEnvString(`LISTEN`))
		}
	}

	if args[0] == `dns` {
		var (
			port               = utils.MustGetEnvInt(`PORT`)
			chinaUpstream      = utils.MustGetEnvString(`CHINA_UPSTREAM`)
			bannedUpstream     = utils.MustGetEnvString(`BANNED_UPSTREAM`)
			chinaDomainsFile   = utils.MustGetEnvString(`CHINA_DOMAINS_FILE`)
			bannedDomainsFile  = utils.MustGetEnvString(`BANNED_DOMAINS_FILE`)
			chinaRoutesFile    = utils.MustGetEnvString(`CHINA_ROUTES_FILE`)
			blockedDomainsFile = utils.MustGetEnvString(`BLOCKED_DOMAINS_FILE`)

			chinaDomains   = rules.ReadGenerated(chinaDomainsFile)
			bannedDomains  = rules.ReadGenerated(bannedDomainsFile)
			blockedDomains = rules.ReadGenerated(blockedDomainsFile)
			chinaRoutes    = rules.ReadGenerated(chinaRoutesFile)
		)

		s := dns.NewServer(int(port),
			chinaUpstream, bannedUpstream,
			chinaDomains, bannedDomains,
			chinaRoutes, blockedDomains,
			tables.WHITE_SET_NAME_4, tables.BLACK_SET_NAME_4,
			tables.WHITE_SET_NAME_6, tables.BLACK_SET_NAME_6,
		)

		utils.Must(s.ListenAndServe())
	}
}

func cmdSetup(cmd *cobra.Command, args []string) {
	mustBeRoot()
	distro, version := targets.GuessTarget()
	if distro == `` {
		log.Fatalln(`无法推断出系统类型，无法完成自动安装。`)
	}

	switch distro {
	case `openwrt`:
		// 24 及以前版本使用 opkg
		if version.Major <= 24 {
			openwrt.Opkg()
			return
		}
		// 25 及以后使用 apk。
		if version.Major >= 25 {
			openwrt.Apk()
			return
		}
	case `ubuntu`:
		ubuntu.Apt()
		return
	case `alpine`:
		alpine.Apk()
		return
	}

	log.Println(`啥也没干。`)
}
