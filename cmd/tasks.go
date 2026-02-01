package cmd

import (
	"syscall"

	"github.com/movsb/gun/dns"
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
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 10000, Max: 10000})

	if args[0] == `outputs` {
		switch args[1] {
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
				utils.MustGetBool(`TROJAN_INSECURE`),
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
	}

	if args[0] == `dns` {
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
	}
}
