package cmd

import (
	"log"
	"os"
	"strings"

	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/spf13/cobra"
)

func mustBeRoot() {
	if os.Geteuid() != 0 {
		log.Fatalln(`需要以 root 用户身份运行此程序。`)
	}
}

func getConfigDir(cmd *cobra.Command) string {
	return utils.Must1(cmd.Flags().GetString(`config-dir`))
}
func addConfigFlag(cmd *cobra.Command) {
	configDir := `/etc/gun`
	wd := utils.Must1(os.Getwd())
	tmp := os.TempDir()
	if wd == tmp || strings.HasPrefix(wd, tmp) || strings.HasPrefix(os.Args[0], tmp) {
		configDir = wd
	}
	cmd.PersistentFlags().StringP(`config-dir`, `c`, configDir, `配置文件目录。`)
}

func cmdExec(cmd *cobra.Command, args []string) {
	mustBeRoot()
	group := targets.GetGroupID(args[0])
	args = args[1:]
	shell.Run(args[0], shell.WithArgs(args[1:]...), shell.WithGID(group), shell.WithSilent(),
		shell.WithStdin(os.Stdin), shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
	)
}
