package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/speed"
	"github.com/movsb/gun/pkg/tables"
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
	cmd.PersistentFlags().StringP(`config-dir`, `c`, configDir, `配置文件目录。`)
}

func cmdDirect(cmd *cobra.Command, args []string) {
	mustBeRoot()
	group := targets.GetGroupID(tables.OutputsGroupName)
	shell.Run(args[0], shell.WithArgs(args[1:]...), shell.WithGID(group), shell.WithSilent(),
		shell.WithStdin(os.Stdin), shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
	)
}

func cmdSpeed(cmd *cobra.Command, args []string) {
	r := speed.Test(cmd.Context())

	output := func(name string, r speed.Result) {
		if r.Error != nil {
			fmt.Printf("%-12s: %v\n", name, r.Error)
		} else {
			fmt.Printf("%-12s: %v\n", name, r.Latency)
		}
	}

	output(`Google`, r.Google)
	output(`YouTube`, r.YouTube)
	output(`GitHub`, r.GitHub)
	output(`Wikipedia`, r.Wikipedia)
	output(`Netflix`, r.Netflix)
	output(`Baidu`, r.Baidu)
}
