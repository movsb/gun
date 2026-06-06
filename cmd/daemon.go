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
		start(context.Background(), configDir, &state)
		time.Sleep(time.Second * 3)
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
