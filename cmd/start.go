package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/movsb/gun/cmd/configs"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/spf13/cobra"
)

func cmdStart(cmd *cobra.Command, args []string) {
	mustBeRoot()
	targets.CheckCommands()

	configDir := getConfigDir(cmd)
	config := configs.LoadConfigFromFile(filepath.Join(configDir, configs.DefaultConfigFileName))

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

	start(ctx, configDir, config)

	go httpServe(ctx)

	time.Sleep(time.Second)
	log.Println(`一切就绪。`)

	<-ctx.Done()
}

func start(ctx context.Context, configDir string, config *configs.Config) {
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
	if config.Outputs.Current == `` {
		panic(`没有指定使用哪个输出(config.outputs.current)。`)
	}
	var output *configs.OutputConfig
	for _, item := range config.Outputs.Stocks {
		if item.Key == config.Outputs.Current {
			copy := item.Value
			output = &copy
			break
		}
	}
	if output == nil {
		panic(`指定的输出在库存中找不到。`)
	}

	// 需要在代理进程组。
	psh := sh.Bind(shell.WithGID(states.ProxyGroupID))

	switch {
	case output.HTTP2Socks != nil:
		c := output.HTTP2Socks
		go psh.Run(`${self} tasks outputs http2socks`,
			shell.WithEnv(`SERVER`, c.Server),
			shell.WithEnv(`TOKEN`, c.Token),
		)
	case output.Trojan != nil:
		c := output.Trojan
		go psh.Run(`${self} tasks outputs trojan`,
			shell.WithEnv(`TROJAN_SERVER`, c.Server),
			shell.WithEnv(`TROJAN_PASSWORD`, c.Password),
			shell.WithEnv(`TROJAN_INSECURE`, c.InsecureSkipVerify),
			shell.WithEnv(`TROJAN_SNI`, c.SNI),
		)
	case output.SSH != nil:
		c := output.SSH
		go psh.Run(`${self} tasks outputs ssh`,
			shell.WithEnv(`SSH_USERNAME`, c.Username),
			shell.WithEnv(`SSH_PASSWORD`, c.Password),
			shell.WithEnv(`SSH_SERVER`, c.Server),
		)
	case output.Socks5 != nil:
		c := output.Socks5
		go psh.Run(`${self} tasks outputs socks5`,
			shell.WithEnv(`SOCKS5_SERVER`, c.Server),
		)
	default:
		panic(`未指定具体的输出配置项。`)
	}
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
