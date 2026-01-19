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

	"github.com/movsb/gun/pkg/dns"
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
	chinaDomainsFile := states.ChinaDomainsFile()
	bannedDomainsFile := states.BannedDomainsFile()

	log.Println(`启动DNS进程...`)
	dns.StartChinaDNS(ctx,
		dnsLocals, dnsRemotes,
		chinaDomainsFile, bannedDomainsFile,
		tables.WHITE_SET_NAME_4, tables.WHITE_SET_NAME_6,
		tables.BLACK_SET_NAME_4, tables.BLACK_SET_NAME_6,
		states.DirectGroupID,
		exited,
	)
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
