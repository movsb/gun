package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/movsb/gun/pkg/dns"
	"github.com/movsb/gun/pkg/rules"
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
	start()
}

func start() {
	ctx, cancel := context.WithCancel(context.Background())
	defer time.Sleep(time.Second)
	defer cancel()

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
	)
}

func cmdStop(cmd *cobra.Command, args []string) {
	stop()
}

func stop() {
	tables.DeleteChains(`iptables-legacy`)
	tables.DeleteChains(`ip6tables-legacy`)
	tables.DeleteIPRoute(tables.IPv4)
	tables.DeleteIPRoute(tables.IPv6)
	tables.DeleteIPSet()
}
