package cmd

import (
	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func AddCommands(rootCmd *cobra.Command) {
	addConfigFlag(rootCmd)

	rootCmd.AddGroup(
		&cobra.Group{ID: `daily`, Title: `日常命令`},
		&cobra.Group{ID: `manage`, Title: `维护命令`},
	)

	statusCmd := &cobra.Command{
		Use:     `status`,
		Short:   `查看运行状态、基本网络访问状态。`,
		GroupID: `daily`,
		Run: func(cmd *cobra.Command, args []string) {
			cmdStatus(cmd, args)
		},
	}
	rootCmd.AddCommand(statusCmd)

	startCmd := &cobra.Command{
		Use:     `start`,
		Short:   `一键重新启动服务(域名服务、代理进程等)。`,
		GroupID: `daily`,
		Run: func(cmd *cobra.Command, args []string) {
			showLogs := utils.Must1(cmd.Flags().GetBool(`logs`))
			cmdStart(cmd, args, showLogs)
		},
	}
	startCmd.Flags().BoolP(`logs`, `l`, false, `是否显示日志。`)
	rootCmd.AddCommand(startCmd)

	stopCmd := &cobra.Command{
		Use:     `stop`,
		Run:     cmdStop,
		GroupID: `daily`,
		Short:   `停止并还原系统状态(不包括：内核参数、用户组)。`,
	}
	rootCmd.AddCommand(stopCmd)

	speedCmd := &cobra.Command{
		Use:     `speed`,
		Short:   `测试常用网站的打开速度(基于TLS拨号)。`,
		GroupID: `daily`,
		Run:     cmdSpeed,
	}
	rootCmd.AddCommand(speedCmd)

	logsCmd := &cobra.Command{
		Use: `logs`,
		Run: func(cmd *cobra.Command, args []string) {
			tail := utils.Must1(cmd.Flags().GetInt(`tail`))
			follow := utils.Must1(cmd.Flags().GetBool(`follow`))
			cmdLogs(cmd, args, tail, follow)
		},
		GroupID: `daily`,
		Short:   `查看历史日志/实时日志（可自动跟随）。`,
	}
	logsCmd.Flags().IntP(`tail`, `t`, 20, `查看最近多少条日志`)
	logsCmd.Flags().BoolP(`follow`, `f`, false, `跟随实时日志`)
	rootCmd.AddCommand(logsCmd)

	setupCmd := &cobra.Command{
		Use:     `setup`,
		Short:   `推测系统版本并安装必要的系统工具。`,
		GroupID: `manage`,
		Run:     cmdSetup,
	}
	setupCmd.Flags().Bool(`no-update`, false, `跳过更新包列表的步骤。`)
	rootCmd.AddCommand(setupCmd)

	updateCmd := &cobra.Command{
		Use:     `update`,
		Short:   `安全地更新全部的规则配置文件。`,
		GroupID: `manage`,
		Run:     cmdUpdate,
	}
	rootCmd.AddCommand(updateCmd)

	directCmd := &cobra.Command{
		Use:                `direct <command> [args]...`,
		Short:              `直接运行命令，不进行代理。`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		Run:                cmdDirect,
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
