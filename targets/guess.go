package targets

import (
	"os"
	"strconv"
	"strings"

	"github.com/movsb/gun/pkg/utils"
)

type Version struct {
	Major int
	Minor int
}

func parseVersion(v string) (out Version) {
	if v == `` {
		panic(`invalid version:` + v)
	}
	if v[0] == 'v' {
		v = v[1:]
	}
	vs := strings.Split(v, `.`)
	out.Major = utils.Must1(strconv.Atoi(vs[0]))
	if len(vs) >= 2 {
		before, _, _ := strings.Cut(vs[1], `-`)
		out.Minor = utils.Must1(strconv.Atoi(before))
	}
	return
}

func GuessTarget() (distro string, version Version) {
	targets := map[string]func() string{
		`openwrt`: guessOpenWRT,
		`ubuntu`:  guessUbuntu,
		`alpine`:  guessAlpine,
		`debian`:  guessDebian,
	}
	for distro, fn := range targets {
		ver := fn()
		if ver == `` {
			continue
		}
		return distro, parseVersion(ver)
	}

	return
}

func guessOpenWRT() string {
	return parseKeyValueFile(`/etc/openwrt_release`, ``, ``, `DISTRIB_RELEASE`)
}

func guessUbuntu() string {
	return parseKeyValueFile(`/etc/os-release`, `ID`, `ubuntu`, `VERSION_ID`)
}

func guessDebian() string {
	return parseKeyValueFile(`/etc/os-release`, `ID`, `debian`, `VERSION_ID`)
}

func guessAlpine() (version string) {
	data, err := os.ReadFile(`/etc/alpine-release`)
	if err != nil {
		return
	}

	return string(data)
}

// 解析文件，如果文件中包含 key=value 的行，则返回 expectKey 的值。
// 如果值包含引号，会自动去掉双引号/单引号。
func parseKeyValueFile(path string, key, value string, expectKey string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ``
	}

	foundKey := false
	foundValue := ``

	// key 的顺序不确定，不要着急 break 出来。
	for line := range strings.SplitSeq(string(data), "\n") {
		parts := strings.SplitN(line, `=`, 2)
		if len(parts) == 2 {
			if key != `` && parts[0] == key && parts[1] == value {
				foundKey = true
			}
			if parts[0] == expectKey {
				foundValue = parts[1]
				if len(foundValue) >= 2 && foundValue[0] == '"' && foundValue[len(foundValue)-1] == '"' {
					foundValue = foundValue[1 : len(foundValue)-1]
				}
				if len(foundValue) >= 2 && foundValue[0] == '\'' && foundValue[len(foundValue)-1] == '\'' {
					foundValue = foundValue[1 : len(foundValue)-1]
				}
			}
		}
	}

	if key == `` || foundKey {
		return foundValue
	}

	return ``
}
