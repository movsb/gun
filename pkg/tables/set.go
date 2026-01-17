package tables

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
)

const (
	SET_NAME_PREFIX  = `gun_`
	WHITE_SET_NAME_4 = `gun_white_4`
	WHITE_SET_NAME_6 = `gun_white_6`
	BLACK_SET_NAME_4 = `gun_black_4`
	BLACK_SET_NAME_6 = `gun_black_6`
)

const (
	TPROXY_SERVER_IP_4 = `127.0.0.1`
	TPROXY_SERVER_IP_6 = `::1`
	TPROXY_SERVER_PORT = `60080`
)

var tproxyValues = shell.WithMaps(map[string]any{
	`TPROXY_SERVER_IP_4`: TPROXY_SERVER_IP_4,
	`TPROXY_SERVER_IP_6`: TPROXY_SERVER_IP_6,
	`TPROXY_SERVER_PORT`: TPROXY_SERVER_PORT,
	`TPROXY_MARK`:        `0x2333`,
})

// 创建黑白IP名单集。
//
// 应该包含文件中的和DNS服务器。
func CreateIPSet(white4, black4, white6, black6 []string) {
	_createIPSet(WHITE_SET_NAME_4, IPv4, white4)
	_createIPSet(WHITE_SET_NAME_6, IPv6, white6)
	_createIPSet(BLACK_SET_NAME_4, IPv4, black4)
	_createIPSet(BLACK_SET_NAME_6, IPv6, black6)
}

// 删除黑白IP名单集。
func DeleteIPSet() {
	output := shell.Run(`ipset -n list`, shell.WithSilent())
	for p := range strings.SplitSeq(output, "\n") {
		if !strings.HasPrefix(p, SET_NAME_PREFIX) {
			continue
		}
		shell.Run(`ipset destroy ${name}`, shell.WithValues(`name`, p))
	}
}

func _createIPSet(name string, family Family, ips []string) {
	values := shell.WithValues(
		`name`, name,
		`family`, utils.IIF(family == IPv4, `inet`, `inet6`),
	)
	shell.Run(`ipset create ${name} hash:net family ${family}`, values)

	buf := bytes.NewBuffer(nil)
	for _, ip := range ips {
		fmt.Fprintln(buf, `add`, name, ip)
	}
	shell.Run(`ipset -! restore`, shell.WithStdin(buf))
}
