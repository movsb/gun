package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/movsb/gun/pkg/speed"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/spf13/cobra"
)

// start 启动 daemon，daemon 启动其它进程。
func cmdDaemon(cmd *cobra.Command, args []string) {
	mux := http.NewServeMux()

	// 由于是后台进程，把标准输出和标准错误重定向一下更方便看日志。
	logger := utils.NewLogger(10<<20, 50_000)
	utils.Must(logger.CaptureStdoutStderr())
	logger.Serve(mux)

	mux.HandleFunc(`/v1/status`, serveStatus)

	var state atomic.Value
	mux.HandleFunc(`/v1/ready`, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, state.Load())
	})

	go httpServe(logSocketPath, mux)

	configDir := utils.MustGetEnvString(`CONFIG_DIR`)

	for {
		ctx, cancel := context.WithCancel(context.Background())
		originalDnsGid := make(chan uint32, 1)
		go watchOriginalDNSServer(ctx, cancel, originalDnsGid)

		start(ctx, configDir, &state, originalDnsGid)
		cancel()
		time.Sleep(time.Second * 3)
	}
}

// 原生 DNS 服务器是可选的，且可能比 gun 更晚启动或者在运行中退出。
// 它的状态发生变化时，重新启动当前一轮，让 DNS 上游和 iptables 规则一起更新。
func watchOriginalDNSServer(ctx context.Context, cancel context.CancelFunc, initialGID <-chan uint32) {
	var originalGID uint32
	select {
	case <-ctx.Done():
		return
	case originalGID = <-initialGID:
	}

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentGID := targets.OriginalDNSServerGroupID()
			if currentGID != originalGID {
				log.Printf(`检测到原生 DNS 状态变化：GID %d -> %d，重新启动...`, originalGID, currentGID)
				cancel()
				return
			}
		}
	}
}

func httpServe(path string, mux *http.ServeMux) {
	if info, _ := os.Lstat(path); info != nil {
		if info.Mode()&os.ModeSocket != 0 {
			os.Remove(path)
		} else {
			panic(`not socket file`)
		}
	}
	lis := utils.Must1(net.Listen(`unix`, path))
	defer lis.Close()
	http.Serve(lis, mux)
}

func cmdStatus(cmd *cobra.Command, args []string) {
	rsp, err := httpClient().Get(`http://gun/v1/status`)
	if err != nil {
		if strings.Contains(err.Error(), `connection refused`) {
			log.Fatalln(`未运行。`)
		}
		log.Fatalln(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf(`服务器返回错误：%s`, rsp.Status))
	}
	utils.Must1(io.Copy(os.Stdout, rsp.Body))
}

func serveStatus(w http.ResponseWriter, r *http.Request) {
	status := struct {
		Processes struct {
			Daemon bool `yaml:"daemon"`
		} `yaml:"processes"`
		Latencies struct {
			Google string `yaml:"google"`
			Baidu  string `yaml:"baidu"`
		} `yaml:"latencies"`
	}{}

	// 此响应是由 daemon 提供的，肯定在运行。
	status.Processes.Daemon = true

	speedResults := speed.Test(r.Context())
	status.Latencies.Google = speedResults.Google.String()
	status.Latencies.Baidu = speedResults.Baidu.String()

	yaml.NewEncoder(w).Encode(status)
}

var httpClient = sync.OnceValue(func() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, `unix`, logSocketPath)
			},
		},
	}
})
