package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/movsb/gun/admin"
	"github.com/movsb/gun/admin/tests/speeds"
	"github.com/movsb/gun/dns"
	"github.com/movsb/gun/outputs/http2socks"
	"github.com/movsb/gun/outputs/ssh"
	"github.com/movsb/gun/outputs/trojan"
	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/movsb/gun/targets/alpine"
	"github.com/movsb/gun/targets/openwrt"
	"github.com/movsb/gun/targets/ubuntu"
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

	configDir := getConfigDir(cmd)

	fmt.Println(`正在更新中国域名列表...`)
	rules.UpdateChinaDomains(ctx, configDir)

	fmt.Println(`正在更新被墙域名列表...`)
	rules.UpdateGFWDomains(ctx, configDir)

	fmt.Println(`正在更新中国路由列表...`)
	rules.UpdateChinaRoutes(ctx, configDir)

	if !utils.FileExists(rules.BannedUserTxt) {
		fmt.Println(`写入被墙的额外列表...`)
		utils.Must(os.WriteFile(filepath.Join(configDir, rules.BannedUserTxt), rules.BannedDefaultText, 0644))
	}
	if !utils.FileExists(rules.IgnoredUserTxt) {
		fmt.Println(`写入直连的额外列表...`)
		utils.Must(os.WriteFile(filepath.Join(configDir, rules.IgnoredUserTxt), rules.IgnoredDefaultText, 0644))
	}
	if !utils.FileExists(rules.BlockedUserTxt) {
		fmt.Println(`写入默认被屏蔽的域名列表...`)
		utils.Must(os.WriteFile(filepath.Join(configDir, rules.BlockedUserTxt), rules.BlockedDefaultTxt, 0644))
	}
}

func cmdStart(cmd *cobra.Command, args []string) {
	mustBeRoot()
	targets.CheckCommands()

	configDir := getConfigDir(cmd)

	// 启动之前总是清理一遍，防止上次启动的时候可能的没清理干净。
	stop()

	defer func() {
		if e := recover(); e != nil {
			log.Println(e)
		}
		log.Println(`还原系统状态...`)
		stop()
		log.Println(`已还原系统状态。`)
	}()

	// 等待HTTP服务器结束或进程被kill（因为context结束）。
	defer time.Sleep(time.Second)

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	start(ctx, configDir)

	go httpServe(ctx)

	time.Sleep(time.Second)
	log.Println(`一切就绪。`)

	<-ctx.Done()
}

func start(ctx context.Context, configDir string) {
	var (
		dnsLocals  = []string{`223.5.5.5`, `240c::6666`}
		dnsRemotes = []string{`8.8.8.8`, `2001:4860:4860::8888`}
	)

	log.Println(`加载数据、检查系统状态...`)
	states := targets.LoadStates(configDir)

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
	tables.DropQUIC(states.Ip4tables, tables.IPv4)
	tables.DropQUIC(states.Ip6tables, tables.IPv6)

	log.Println(`转发DNS请求...`)
	tables.ProxyDNS(states.Ip4tables, tables.IPv4)
	tables.ProxyDNS(states.Ip6tables, tables.IPv6)

	log.Println(`转发TCP/UDP到TPROXY...`)
	tables.TProxy(states.Ip4tables, tables.IPv4, true, true)
	tables.TProxy(states.Ip6tables, tables.IPv6, true, true)

	sh := shell.Bind(
		shell.WithContext(ctx), shell.WithCmdSelf(),
		shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
		shell.WithIgnoreErrors(`signal: interrupt`, `context canceled`, `signal: killed`),
	)

	log.Println(`启动域名进程...`)
	// 启动DNS进程。
	// 需要在直连进程组。
	go sh.Run(`${self} tasks dns`,
		shell.WithGID(states.DirectGroupID),
		shell.WithEnv(`PORT`, tables.DNSPort),
		shell.WithEnv(`CHINA_UPSTREAM`, `223.5.5.5`),
		shell.WithEnv(`BANNED_UPSTREAM`, `8.8.8.8`),
		shell.WithEnv(`CHINA_DOMAINS_FILE`, states.ChinaDomainsFile()),
		shell.WithEnv(`BANNED_DOMAINS_FILE`, states.BannedDomainsFile()),
		shell.WithEnv(`BLOCKED_DOMAINS_FILE`, states.BlockedDomainsFile()),
		shell.WithEnv(`CHINA_ROUTES_FILE`, states.ChinaRoutesFile()),
	)

	log.Println(`启动代理进程...`)
	// 需要在代理进程组。
	go sh.Run(`${self} tasks outputs http2socks`,
		shell.WithGID(states.ProxyGroupID),
		shell.WithEnv(`SERVER`, utils.MustGetEnvString(`HTTP2SOCKS_SERVER`)),
		shell.WithEnv(`TOKEN`, utils.MustGetEnvString(`HTTP2SOCKS_TOKEN`)),
	)
	// go sh.Run(`${self} tasks outputs trojan`,
	// 	shell.WithGID(states.ProxyGroupID),
	// 	shell.WithEnv(`TROJAN_SERVER`, ``),
	// 	shell.WithEnv(`TROJAN_PASSWORD`, ``),
	// 	shell.WithEnv(`TROJAN_INSECURE`, true),
	// 	shell.WithEnv(`TROJAN_SNI`, ``),
	// )
}

func cmdStop(cmd *cobra.Command, args []string) {
	mustBeRoot()
	stop()
}

func stop() {
	utils.KillChildren()
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

	if args[0] == `outputs` {
		switch args[1] {
		case `http2socks`:
			http2socks.ListenAndServeTProxy(
				tables.TPROXY_SERVER_PORT,
				utils.MustGetEnvString(`SERVER`),
				utils.MustGetEnvString(`TOKEN`),
			)
		case `trojan`:
			trojan.ListenAndServeTProxy(
				tables.TPROXY_SERVER_PORT,
				utils.MustGetEnvString(`TROJAN_SERVER`),
				utils.MustGetEnvString(`TROJAN_PASSWORD`),
				utils.MustGetBool(`TROJAN_INSECURE`),
				utils.MustGetEnvString(`TROJAN_SNI`),
			)
		case `ssh`:
			client := ssh.New(
				utils.MustGetEnvString(`SSH_USERNAME`),
				utils.MustGetEnvString(`SSH_PASSWORD`),
				utils.MustGetEnvString(`SSH_SERVER`),
			)
			client.ListenAndServeTProxy(tables.TPROXY_SERVER_PORT)
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

	configDir := getConfigDir(cmd)
	utils.Must(os.MkdirAll(configDir, 0700))

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

func cmdServe(cmd *cobra.Command, args []string) {
	httpServe(cmd.Context())
}

func cmdSpeed(cmd *cobra.Command, args []string) {
	r := speeds.Test(cmd.Context())

	output := func(name string, r speeds.Result) {
		if r.Error != nil {
			fmt.Printf("%-12s: %v\n", name, r.Error)
		} else {
			fmt.Printf("%-12s: %v\n", name, r.Latency)
		}
	}

	output(`Google`, r.Google)
	output(`YouTube`, r.YouTube)
	output(`GitHub`, r.GitHub)
	output(`BaiDu`, r.BaiDu)
}
