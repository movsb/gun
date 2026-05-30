package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/movsb/gun/cmd/configs"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/spf13/cobra"
)

const logSocketPath = `/tmp/gun.sock`

func cmdLogs(cmd *cobra.Command, args []string) {
	tail := utils.Must1(cmd.Flags().GetInt(`tail`))
	printLogs(cmd.Context(), tail)
}

func printLogs(_ context.Context, tail int) {
	rsp, err := httpClient().Get(`http://gun/v1/logs?tail=` + strconv.Itoa(tail))
	if err != nil {
		log.Fatalln(err)
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf(`日志服务器返回错误：%s`, rsp.Status))
	}

	utils.Must1(io.Copy(os.Stdout, rsp.Body))
}

func cmdStart(cmd *cobra.Command, _ []string, showLogs bool) {
	mustBeRoot()
	targets.CheckCommands()

	configDir := getConfigDir(cmd)

	// 启动之前总是清理一遍，防止上次启动的时候可能的没清理干净。
	stop()

	// Detach会启动但不等待。
	// 但是如果进程启动后就退出了，仍然会进行错误处理。
	shell.Run(`${self} daemon`,
		shell.WithCmdSelf(),
		shell.WithDetach(),
		shell.WithCombined(os.Stderr),
		shell.WithEnv(`CONFIG_DIR`, configDir),
	)

	for {
		rsp, err := httpClient().Get(`http://gun/v1/ready`)
		if err != nil {
			if strings.Contains(err.Error(), `refused`) || strings.Contains(err.Error(), `no such file`) {
				time.Sleep(time.Millisecond * 250)
				continue
			}
			log.Fatalln(err)
		}
		defer rsp.Body.Close()
		ready := strings.TrimSpace(string(utils.Must1(io.ReadAll(rsp.Body))))
		if ready != `true` {
			time.Sleep(time.Millisecond * 250)
			continue
		}
		break
	}

	log.Println(`已启动。`)

	if showLogs {
		printLogs(cmd.Context(), -1)
	}
}

// 启动一切，并等待结束。
// 结束条件：ctx结束、ctrl-c。
func start(ctx context.Context, configDir string, ready chan struct{}) {
	defer func() {
		if e := recover(); e != nil {
			log.Println(e)
		}
		log.Println(`还原系统状态...`)
		stop()
		log.Println(`已还原系统状态。`)
	}()

	// 等待HTTP服务器结束或进程被kill（因为context结束）。
	defer time.Sleep(time.Second)

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer cancel()

	config := configs.LoadConfigFromFile(filepath.Join(configDir, configs.DefaultConfigFileName))

	func() {
		log.Println(`加载数据、检查系统状态...`)
		states := targets.LoadStates(configDir)

		states.SetDNSUpstreams(config.DNS.Upstreams.China, config.DNS.Upstreams.Banned)

		hasUDP := startProcesses(ctx, states, config, configDir)
		startRules(states, hasUDP)
	}()
	runtime.GC()

	time.Sleep(time.Second)
	log.Println(`一切就绪。`)

	close(ready)
	<-ctx.Done()
}

func startRules(states *targets.State, hasUDP bool) {
	log.Println(`设置内核参数...`)
	tables.SetKernelParams()

	log.Println(`创建表和链...`)
	tables.CreateChains(states.Ip4tables)
	tables.CreateChains(states.Ip6tables)

	log.Println(`创建黑白IP列表集...`)
	tables.CreateIPSet(states.White4(), states.Black4(), states.White6(), states.Black6())

	log.Println(`添加系统路由...`)
	tables.CreateIPRoute(tables.IPv4)
	tables.CreateIPRoute(tables.IPv6)

	// 没有UDP代理的情况下……
	//
	// 其实可以直接不接管UDP，任由其发送。
	if !hasUDP {
		// QUIC应该主动丢弃，增加响应时间。
		// 另外，OpenAI会使用QUIC连接，会导致误判为中国，从而禁止使用。
		tables.DropQUIC(states.Ip4tables, tables.IPv4)
		tables.DropQUIC(states.Ip6tables, tables.IPv6)
		// 同时把mDNS（内网DNS广播和NTP时间协议）主动放行。
		tables.AllowMDNS(states.Ip4tables)
		tables.AllowMDNS(states.Ip6tables)
		tables.AllowNTP(states.Ip4tables)
		tables.AllowNTP(states.Ip6tables)
	}

	log.Println(`转发DNS请求...`)
	tables.ProxyDNS(states.Ip4tables, tables.IPv4, states.OriginalDNSServerGroupID)
	tables.ProxyDNS(states.Ip6tables, tables.IPv6, states.OriginalDNSServerGroupID)

	log.Println(`转发TCP/UDP到TPROXY...`)
	tables.TProxy(states.Ip4tables, tables.IPv4)
	tables.TProxy(states.Ip6tables, tables.IPv6)
}

func startProcesses(ctx context.Context, states *targets.State, config *configs.Config, configDir string) (outputSupportsUDP bool) {
	sh := shell.Bind(
		shell.WithContext(ctx), shell.WithCmdSelf(),
		shell.WithStdout(os.Stdout), shell.WithStderr(os.Stderr),
		shell.WithIgnoreErrors(`signal: interrupt`, `context canceled`, `signal: killed`),
	)

	log.Println(`启动域名进程...`)
	// 启动DNS进程。
	// 需要在域名进程组。
	go sh.Run(`${self} tasks dns`,
		shell.WithAutoRestart(),
		shell.WithGID(states.DNSGroupID),
		shell.WithEnv(`PORT`, tables.DNSPort),
		shell.WithEnv(`CHINA_UPSTREAM`, states.ChinaDNS),
		shell.WithEnv(`BANNED_UPSTREAM`, states.BannedDNS),
		shell.WithEnv(`CHINA_DOMAINS_FILE`, states.ChinaDomainsFile()),
		shell.WithEnv(`BANNED_DOMAINS_FILE`, states.BannedDomainsFile()),
		shell.WithEnv(`BLOCKED_DOMAINS_FILE`, states.BlockedDomainsFile()),
		shell.WithEnv(`CHINA_ROUTES_FILE`, states.ChinaRoutesFile()),
	)

	log.Println(`启动代理进程...`)
	current := config.Outputs.Current
	if current == `` {
		panic(`没有指定使用哪个输出(config.outputs.current)。`)
	}

	// 当前选择的输出端，如果为空，为直连。
	var output *configs.OutputConfig

	if current != `direct` {
		for _, item := range config.Outputs.Stocks {
			if item.Key == current {
				copy := item.Value
				output = &copy
				break
			}
		}
		if output == nil {
			panic(`指定的输出在库存中找不到。`)
		}
	}

	// 需要在直连/输出进程组。
	psh := sh.Bind(
		shell.WithAutoRestart(),
		shell.WithGID(states.OutputsGroupID),
	)

	switch {
	case output == nil:
		// 暂时不支持，还没实现。
		// outputSupportsUDP = true
		go psh.Run(`${self} tasks outputs direct`)
	case output.HTTP2Socks != nil:
		c := output.HTTP2Socks
		go psh.Run(`${self} tasks outputs http2socks`,
			shell.WithEnv(`SERVER`, c.Server),
			shell.WithEnv(`TOKEN`, c.Token),
		)
	case output.Trojan != nil:
		c := output.Trojan
		go psh.Run(`${self} tasks outputs trojan`,
			shell.WithEnv(`TROJAN_SERVER`, c.Server),
			shell.WithEnv(`TROJAN_PASSWORD`, c.Password),
			shell.WithEnv(`TROJAN_INSECURE`, c.Insecure),
			shell.WithEnv(`TROJAN_SNI`, c.SNI),
		)
	case output.SSH != nil:
		c := output.SSH
		go psh.Run(`${self} tasks outputs ssh`,
			shell.WithEnv(`SSH_USERNAME`, c.Username),
			shell.WithEnv(`SSH_PASSWORD`, c.Password),
			shell.WithEnv(`SSH_SERVER`, c.Server),
			shell.WithEnv(`SSH_FINGERPRINT`, c.Fingerprint),
		)
	case output.Socks5 != nil:
		c := output.Socks5
		go psh.Run(`${self} tasks outputs socks5`,
			shell.WithEnv(`SOCKS5_SERVER`, c.Server),
		)
	case output.NaiveProxy != nil:
		c := output.NaiveProxy

		bin := c.Bin
		if bin == `` {
			bin = filepath.Join(configDir, `naive`)
		}

		go psh.Run(`${self} tasks outputs naive_proxy`,
			shell.WithEnv(`GUN_CHILD`, 1),
			shell.WithEnv(`UID`, states.NobodyID),
			shell.WithEnv(`GID`, states.OutputsGroupID),
			shell.WithEnv(`NAIVE_BIN`, bin),
			shell.WithEnv(`NAIVE_SERVER`, c.Server),
			shell.WithEnv(`NAIVE_USERNAME`, c.Username),
			shell.WithEnv(`NAIVE_PASSWORD`, c.Password),
		)
	case output.Hysteria != nil:
		c := output.Hysteria
		bin := c.Bin
		if bin == `` {
			bin = filepath.Join(configDir, `hysteria`)
		}
		nobody := psh.Bind(shell.WithUID(states.NobodyID))
		runHysteria(nobody, bin, c.Server, c.Password, tables.TPROXY_SERVER_PORT)
		outputSupportsUDP = true
	default:
		panic(`未指定具体的输出配置项。`)
	}

	return
}

func cmdStop(cmd *cobra.Command, args []string) {
	mustBeRoot()
	stop()
}

func stop() {
	utils.KillChildren()
	ip4, ip6 := targets.FindIPTablesCommands()
	tables.DeleteChains(ip4)
	tables.DeleteChains(ip6)
	tables.DeleteIPRoute(tables.IPv4)
	tables.DeleteIPRoute(tables.IPv6)
	tables.DeleteIPSet()
}
