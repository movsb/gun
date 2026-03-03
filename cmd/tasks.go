package cmd

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"syscall"
	"time"

	"github.com/movsb/gun/dns"
	"github.com/movsb/gun/outputs/direct"
	"github.com/movsb/gun/outputs/http2socks"
	"github.com/movsb/gun/outputs/socks5"
	"github.com/movsb/gun/outputs/ssh"
	"github.com/movsb/gun/outputs/trojan"
	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func cmdTasks(cmd *cobra.Command, args []string) {
	go http.ListenAndServe(`localhost:0`, nil)

	setLimit := func() {
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 10000, Max: 10000})
	}

	if args[0] == `outputs` {
		setLimit()
		switch args[1] {
		case `direct`:
			direct.ListenAndServeTProxy(tables.TPROXY_SERVER_PORT)
		case `http2socks`:
			http2socks.ListenAndServeTProxy(
				tables.TPROXY_SERVER_PORT,
				utils.MustGetEnvString(`SERVER`),
				utils.MustGetEnvString(`TOKEN`),
			)
		case `trojan`:
			trojan.ListenAndServeTProxy(
				tables.TPROXY_SERVER_PORT,
				utils.MustGetEnvString(`TROJAN_SERVER`),
				utils.MustGetEnvString(`TROJAN_PASSWORD`),
				utils.MustGetEnvBool(`TROJAN_INSECURE`),
				utils.MustGetEnvString(`TROJAN_SNI`),
			)
		case `ssh`:
			client := ssh.New(
				utils.MustGetEnvString(`SSH_USERNAME`),
				utils.MustGetEnvString(`SSH_PASSWORD`),
				utils.MustGetEnvString(`SSH_SERVER`),
			)
			client.ListenAndServeTProxy(tables.TPROXY_SERVER_PORT)
		case `socks5`:
			socks5.ListenAndServeTProxy(
				tables.TPROXY_SERVER_PORT,
				utils.MustGetEnvString(`SOCKS5_SERVER`),
			)
		}
		return
	}

	if args[0] == `dns` {
		setLimit()
		var (
			port               = utils.MustGetEnvInt(`PORT`)
			chinaUpstream      = utils.MustGetEnvString(`CHINA_UPSTREAM`)
			bannedUpstream     = utils.MustGetEnvString(`BANNED_UPSTREAM`)
			chinaDomainsFile   = utils.MustGetEnvString(`CHINA_DOMAINS_FILE`)
			bannedDomainsFile  = utils.MustGetEnvString(`BANNED_DOMAINS_FILE`)
			chinaRoutesFile    = utils.MustGetEnvString(`CHINA_ROUTES_FILE`)
			blockedDomainsFile = utils.MustGetEnvString(`BLOCKED_DOMAINS_FILE`)

			chinaDomains   = rules.ReadGenerated(chinaDomainsFile)
			bannedDomains  = rules.ReadGenerated(bannedDomainsFile)
			blockedDomains = rules.ReadGenerated(blockedDomainsFile)
			chinaRoutes    = rules.ReadGenerated(chinaRoutesFile)
		)

		s := dns.NewServer(int(port),
			chinaUpstream, bannedUpstream,
			chinaDomains, bannedDomains,
			chinaRoutes, blockedDomains,
			tables.WHITE_SET_NAME_4, tables.BLACK_SET_NAME_4,
			tables.WHITE_SET_NAME_6, tables.BLACK_SET_NAME_6,
		)

		utils.Must(s.ListenAndServe())
		return
	}

	if args[0] == `daemon` {
		pid := utils.MustGetEnvInt(`PID`)
		// ps.Wait 说在大多数操作系统上，该进程应该属于此进程的
		// 子进程才能被等待，所以这里不等它，直接靠Find判断存在其是
		// 否仍然存在。
		for {
			ps, err := os.FindProcess(pid)
			if err != nil {
				break
			}
			// 在 Unix 上始终返回ps，但是需要发信号才能判断。
			err = ps.Signal(syscall.Signal(0))
			if err != nil {
				break
			}
			ps.Release()
			time.Sleep(time.Second * 5)
			continue
		}
		stop()
		return
	}
}
