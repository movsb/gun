package cmd

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/movsb/gun/dns"
	"github.com/movsb/gun/outputs/direct"
	"github.com/movsb/gun/outputs/http2socks"
	"github.com/movsb/gun/outputs/socks5"
	"github.com/movsb/gun/outputs/ssh"
	"github.com/movsb/gun/outputs/trojan"
	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/spf13/cobra"
)

func cmdTasks(cmd *cobra.Command, args []string) {
	// 开启 pprof。
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
		case `naive_proxy`:
			port := runNaiveProxy(
				utils.MustGetEnvInt(`GID`),
				utils.MustGetEnvInt(`UID`),
				utils.MustGetEnvString(`NAIVE_BIN`),
				utils.MustGetEnvString(`NAIVE_SERVER`),
				utils.MustGetEnvString(`NAIVE_USERNAME`),
				utils.MustGetEnvString(`NAIVE_PASSWORD`),
			)
			socks5.ListenAndServeTProxy(
				tables.TPROXY_SERVER_PORT,
				fmt.Sprintf(`127.0.0.1:%d`, port),
			)
		}
		return
	}

	if args[0] == `dns` {
		setLimit()

		// 包装在函数中以回收不必须的局部变量内存。
		create := func() *dns.Server {
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

			return dns.NewServer(int(port),
				chinaUpstream, bannedUpstream,
				chinaDomains, bannedDomains,
				chinaRoutes, blockedDomains,
				tables.WHITE_SET_NAME_4, tables.BLACK_SET_NAME_4,
				tables.WHITE_SET_NAME_6, tables.BLACK_SET_NAME_6,
			)
		}

		s := create()
		runtime.GC()
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

func runNaiveProxy(gid, uid int, bin string, server, username, password string) uint16 {
	if !utils.FileExists(bin) {
		log.Fatalf(`二进制文件未找到：%s`, bin)
	}

	u := utils.Must1(url.Parse(server))
	if username != `` {
		u.User = url.UserPassword(username, password)
	}
	proxy := u.String()
	port := 60000 + uint16(rand.UintN(5536))

	go shell.Run(`${bin} \
		--listen=socks://127.0.0.1:${port} \
		--proxy=${proxy} \
		--log \
		`,
		shell.WithEnv(`GUN_CHILD`, 1),
		shell.WithValues(`bin`, bin),
		shell.WithValues(`port`, port),
		shell.WithValues(`proxy`, proxy),
		shell.WithGID(uint32(gid)),
		shell.WithUID(uint32(uid)),
		shell.WithStdout(os.Stdout),
		shell.WithStderr(os.Stderr),
	)

	return port
}

func runHysteria(gid, uid int, bin string, server, password string, port uint16) {
	if !utils.FileExists(bin) {
		log.Fatalf(`二进制文件未找到：%s`, bin)
	}

	// 外部进程不是以 root 运行的，设置 tproxy 需要以下权限。
	// TODO squashfs 不支持 xattr 可能无法设置，需要拷贝一份。
	shell.Run(`setcap CAP_NET_ADMIN,CAP_NET_BIND_SERVICE+ep ${bin}`, shell.WithValues(`bin`, bin))

	rawConfigYaml := `
server: %s
auth: %s
tcpTProxy:
  listen: 127.0.0.1:%d
udpTProxy:
  listen: 127.0.0.1:%d 
`

	rawConfigYaml = fmt.Sprintf(rawConfigYaml, server, password, port, port)

	tmpFile := utils.Must1(os.Create(`/tmp/_gun_hysteria.yaml`))
	utils.Must1(tmpFile.WriteString(rawConfigYaml))
	tmpFile.Close()

	go shell.Run(`${bin} client -c ${config}`,
		shell.WithEnv(`GUN_CHILD`, 1),
		shell.WithValues(`bin`, bin),
		shell.WithValues(`config`, tmpFile.Name()),
		shell.WithGID(uint32(gid)),
		shell.WithUID(uint32(uid)),
		shell.WithStdout(os.Stdout),
		shell.WithStderr(os.Stderr),
	)
}
