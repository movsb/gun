package cmd

import (
	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func AddCommands(rootCmd *cobra.Command) {
	addConfigFlag(rootCmd)

	setupCmd := &cobra.Command{
		Use:   `setup`,
		Short: `推测系统版本并安装必要的系统工具。`,
		Run:   cmdSetup,
	}
	setupCmd.Flags().Bool(`no-update`, false, `跳过更新包列表的步骤。`)
	rootCmd.AddCommand(setupCmd)

	startCmd := &cobra.Command{
		Use:   `start`,
		Short: `一键启动服务(域名服务、代理进程等)。`,
		Run: func(cmd *cobra.Command, args []string) {
			showLogs := utils.Must1(cmd.Flags().GetBool(`logs`))
			cmdStart(cmd, args, showLogs)
		},
	}
	startCmd.Flags().BoolP(`logs`, `l`, false, `是否显示日志。`)
	rootCmd.AddCommand(startCmd)

	stopCmd := &cobra.Command{
		Use:   `stop`,
		Run:   cmdStop,
		Short: `手动还原系统状态(不包括：内核参数、用户组)。`,
	}
	rootCmd.AddCommand(stopCmd)

	logsCmd := &cobra.Command{
		Use:   `logs`,
		Run:   cmdLogs,
		Short: `查看历史日志/实时日志（自动跟随）。`,
	}
	logsCmd.Flags().IntP(`tail`, `t`, 20, `查看最近多少条日志`)
	rootCmd.AddCommand(logsCmd)

	updateCmd := &cobra.Command{
		Use:   `update`,
		Short: `安全地更新全部的规则配置文件。`,
		Run:   cmdUpdate,
	}
	rootCmd.AddCommand(updateCmd)

	speedCmd := &cobra.Command{
		Use:   `speed`,
		Short: `测试常用网站的打开速度(基于TLS拨号)。`,
		Run:   cmdSpeed,
	}
	rootCmd.AddCommand(speedCmd)

	directCmd := &cobra.Command{
		Use:                `direct <command> [args]...`,
		Short:              `直接运行命令，不进行代理。`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		Run:                cmdDirect,
		Hidden:             true,
	}
	rootCmd.AddCommand(directCmd)

	daemonCmd := &cobra.Command{
		Use:    `daemon`,
		Hidden: true,
		Run:    cmdDaemon,
	}
	rootCmd.AddCommand(daemonCmd)

	tasksCmd := &cobra.Command{
		Use:    `tasks types...`,
		Hidden: true,
		Run:    cmdTasks,
	}
	rootCmd.AddCommand(tasksCmd)
}
