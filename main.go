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
		Use: `stop`,
		Run: cmdStop,
	}
	rootCmd.AddCommand(startCmd, stopCmd)

	updateCmd := &cobra.Command{
		Use:   `update`,
		Short: `安全地更新全部的规则配置文件。`,
		Run:   cmdUpdate,
	}
	rootCmd.AddCommand(updateCmd)

	rootCmd.Execute()
}
