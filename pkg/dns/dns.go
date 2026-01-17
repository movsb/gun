package dns

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/movsb/gun/pkg/shell"
)

const Port = 60053

// 启动DNS服务器。
//
// 此函数会立即返回，不会阻塞。
//
//   - locals: 本地域名服务器IPv4/IPv6地址列表。
//   - remotes: 远程域名服务器IPv4/IPv6地址列表。
func StartChinaDNS(ctx context.Context,
	localDNSes, remoteDNSes []string,
	chinaDomainFile, bannedDomainFile string,
	whiteSet4, whiteSet6, blackSet4, blackSet6 string,
) {
	// 允许绑定到IPv6的服务器也能处理IPv4
	shell.Run(`sysctl -wq net.ipv6.bindv6only=0`, shell.WithSilent())

	var args []string

	args = append(args, `-b`, `::`)
	args = append(args, `-l`, fmt.Sprint(Port))

	use := func(local bool, servers ...string) {
		for _, s := range servers {
			if local {
				args = append(args, `--china-dns`, s)
			} else {
				if !strings.Contains(s, `://`) {
					s = `tcp://` + s
				}
				args = append(args, `--trust-dns`, s)
			}
		}
	}

	use(true, localDNSes...)
	use(false, remoteDNSes...)

	args = append(args, `--cache`, `4096`)
	args = append(args, `--cache-stale`, `65535`)
	args = append(args, `--cache-refresh`, `20`)
	args = append(args, `--verdict-cache`, `4096`)
	args = append(args, `--cache-db`, `dns-cache.db`)
	args = append(args, `--verdict-cache-db`, `verdict-cache.db`)

	// IPv6 兼容不好，暂时关闭。
	args = append(args, `--no-ipv6`)

	args = append(args, `--chnlist-file`, chinaDomainFile)
	args = append(args, `--gfwlist-file`, bannedDomainFile)
	args = append(args, `--add-tagchn-ip`, fmt.Sprintf(`%s,%s`, whiteSet4, whiteSet6))
	args = append(args, `--add-taggfw-ip`, fmt.Sprintf(`%s,%s`, blackSet4, blackSet6))
	args = append(args, `--ipset-name4`, whiteSet4)
	args = append(args, `--ipset-name6`, whiteSet6)

	go func() {
		defer log.Println(`退出DNS服务器进程...`)
		shell.Run(`chinadns-ng`, shell.WithContext(ctx), shell.WithArgs(args...),
			shell.WithIgnoreErrors(`signal: killed`, `context canceled`),
		)
	}()
}
