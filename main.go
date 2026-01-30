package main

import (
	"os"
	"strings"

	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func init() {
	cobra.EnableCommandSorting = false
}

func getConfigDir(cmd *cobra.Command) string {
	return utils.Must1(cmd.Flags().GetString(`config-dir`))
}
func addConfigFlag(cmd *cobra.Command) {
	configDir := `/etc/gun`
	wd := utils.Must1(os.Getwd())
	tmp := os.TempDir()
	if wd == tmp || strings.HasPrefix(wd, tmp) {
		configDir = wd
	}
	cmd.PersistentFlags().StringP(`config-dir`, `c`, configDir, `配置文件目录。`)
}

func main() {
	rootCmd := &cobra.Command{
		Use: os.Args[0],
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
	}
	addConfigFlag(rootCmd)

	setupCmd := &cobra.Command{
		Use:   `setup`,
		Short: `推测系统版本并安装必要的系统工具和规则文件。`,
		Run:   cmdSetup,
	}
	rootCmd.AddCommand(setupCmd)

	startCmd := &cobra.Command{
		Use:   `start`,
		Short: `一键启动服务(域名服务、接管进程、代理进程)。`,
		Run:   cmdStart,
	}
	rootCmd.AddCommand(startCmd)

	stopCmd := &cobra.Command{
		Use:   `stop`,
		Run:   cmdStop,
		Short: `手动还原系统状态(不包括：内核参数、用户组)。`,
	}
	rootCmd.AddCommand(stopCmd)

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

	execCmd := &cobra.Command{
		Use:                `exec <group-name> <command> [args]...`,
		Short:              `以指定的用户组执行命令。`,
		Args:               cobra.MinimumNArgs(2),
		DisableFlagParsing: true,
		Run:                cmdExec,
		Hidden:             true,
	}
	rootCmd.AddCommand(execCmd)

	tasksCmd := &cobra.Command{
		Use:    `tasks types...`,
		Hidden: true,
		Run:    cmdTasks,
	}
	rootCmd.AddCommand(tasksCmd)

	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	rootCmd.Execute()
}
