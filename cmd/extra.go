package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/movsb/gun/admin"
	"github.com/movsb/gun/admin/tests/speeds"
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

func httpServe(ctx context.Context) {
	h := admin.NewServer()

	s := http.Server{
		Addr:    `0.0.0.0:3486`,
		Handler: h.Handler(),
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

func cmdServe(cmd *cobra.Command, args []string) {
	httpServe(cmd.Context())
}

func cmdSpeed(cmd *cobra.Command, args []string) {
	r := speeds.Test(cmd.Context())

	output := func(name string, r speeds.Result) {
		if r.Error != nil {
			fmt.Printf("%-12s: %v\n", name, r.Error)
		} else {
			fmt.Printf("%-12s: %v\n", name, r.Latency)
		}
	}

	output(`Google`, r.Google)
	output(`YouTube`, r.YouTube)
	output(`GitHub`, r.GitHub)
	output(`BaiDu`, r.BaiDu)
}
