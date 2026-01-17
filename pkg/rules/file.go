package rules

import (
	"bufio"
	"net/netip"
	"os"
	"strings"

	_ "embed"

	"github.com/movsb/gun/pkg/utils"
)

//go:embed banned.default.txt
var BannedDefaultText []byte

//go:embed ignored.default.txt
var IgnoredDefaultText []byte

type File struct {
	IPv4    []string
	IPv6    []string
	Domains []string
}

// 解析一个规则文件。
//
// 内容可以包含域名、IPv4、IPv6、CIDR。
//
// NOTE: 没有判断是合有效。
func Parse(path string) *File {
	f := &File{}
	fp := utils.Must1(os.Open(path))
	defer fp.Close()
	scn := bufio.NewScanner(fp)
	for scn.Scan() {
		line := strings.TrimSpace(scn.Text())
		if len(line) <= 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}

		// 排除IPv6: 包含冒号的一定只可能是IPv6（含CIDR）
		if strings.IndexByte(line, ':') >= 0 {
			f.IPv6 = append(f.IPv6, line)
			continue
		}

		// 包含/的一定是IPv4 CIDR
		if strings.IndexByte(line, '/') >= 0 {
			f.IPv4 = append(f.IPv4, line)
		}

		// 其它：可能是IPv4，可能是域名。
		// 大量数据时性能可能不太好，但是没关系，文件写起来方便就好。
		_, err := netip.ParseAddr(line)
		if err == nil {
			f.IPv4 = append(f.IPv4, line)
		} else {
			f.Domains = append(f.Domains, line)
		}
	}
	if scn.Err() != nil {
		panic(scn.Err())
	}
	return f
}
