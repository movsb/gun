package main

import (
	"os"

	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

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
		Use:   `start`,
		Run:   cmdStart,
		Short: `一键启动。`,
	}
	stopCmd := &cobra.Command{
		Use:   `stop`,
		Run:   cmdStop,
		Short: `停止并恢复系统状态。不会恢复：内核状态、已添加的用户组。`,
	}
	rootCmd.AddCommand(startCmd, stopCmd)
	restartCmd := &cobra.Command{
		Use:   `restart`,
		Short: `停止 & 启动。`,
		Run: func(cmd *cobra.Command, args []string) {
			stop()
			cmdStart(cmd, args)
		},
	}
	rootCmd.AddCommand(restartCmd)

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

	tasksCmd := &cobra.Command{
		Use:    `tasks types...`,
		Hidden: true,
		Run:    cmdTasks,
	}
	rootCmd.AddCommand(tasksCmd)

	setupCmd := &cobra.Command{
		Use:   `setup`,
		Short: `推测系统版本并安装必要的系统工具。`,
		Run:   cmdSetup,
	}
	rootCmd.AddCommand(setupCmd)

	rootCmd.Execute()
}
