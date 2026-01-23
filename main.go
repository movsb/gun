package main

import (
	"os"

	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

// opkg install iptables-legacy ip6tables-legacy ipset kmod-ipt-conntrack iptables-mod-extra(for addrtype)
// kmod-ipt-nat kmod-ipt-nat6 ip6tables-zz-legacy shadow-groupadd iptables-mod-conntrack-extra iptables-mod-tproxy

var verbose bool

func main() {
	rootCmd := &cobra.Command{
		Use: os.Args[0],
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			verbose = utils.Must1(cmd.Flags().GetBool(`verbose`))
		},
	}
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().BoolP(`verbose`, `v`, false, `是否输出更详细的日志。`)

	startCmd := &cobra.Command{
		Use: `start`,
		Run: cmdStart,
	}
	stopCmd := &cobra.Command{
		Use:   `stop`,
		Run:   cmdStop,
		Short: `停止并恢复系统状态。不会恢复：内核状态、已添加的用户组。`,
	}
	rootCmd.AddCommand(startCmd, stopCmd)

	updateCmd := &cobra.Command{
		Use:   `update`,
		Short: `安全地更新全部的规则配置文件。`,
		Run:   cmdUpdate,
	}
	rootCmd.AddCommand(updateCmd)

	execCmd := &cobra.Command{
		Use:                `exec <group-name> <command> [args]...`,
		Short:              `以指定的用户组执行命令。`,
		Args:               cobra.MinimumNArgs(2),
		DisableFlagParsing: true,
		Run:                cmdExec,
	}
	rootCmd.AddCommand(execCmd)

	dnsCmd := &cobra.Command{
		Use:   `dns`,
		Short: `域名解析相关命令。`,
	}
	rootCmd.AddCommand(dnsCmd)
	dnsServerCmd := &cobra.Command{
		Use:   `server`,
		Short: `运行DNS服务器。`,
		Run:   cmdDNSServer,
	}
	dnsServerCmd.Flags().Uint16P(`port`, `p`, 60053, `服务器监听的UDP端口。`)
	dnsServerCmd.Flags().String(`china-upstream`, ``, `中国DNS服务器上游。`)
	dnsServerCmd.Flags().String(`banned-upstream`, ``, `外国DNS服务器上游。`)
	dnsServerCmd.Flags().String(`china-domains-file`, ``, `已知中国域名列表。`)
	dnsServerCmd.Flags().String(`banned-domains-file`, ``, `已知被墙域名列表。`)
	dnsServerCmd.Flags().String(`china-routes-file`, ``, `中国路由列表文件。`)
	dnsServerCmd.Flags().String(`white-set-4`, ``, `IPSet白名单列表名（IPv4）。`)
	dnsServerCmd.Flags().String(`black-set-4`, ``, `IPSet黑名单列表名（IPv4）。`)
	dnsServerCmd.MarkFlagRequired(`china-upstream`)
	dnsServerCmd.MarkFlagsRequiredTogether(
		`china-upstream`, `banned-upstream`,
		`china-domains-file`, `banned-domains-file`,
		`china-routes-file`,
		`white-set-4`, `black-set-4`,
	)
	dnsCmd.AddCommand(dnsServerCmd)

	rootCmd.Execute()
}
