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
		out.Minor = utils.Must1(strconv.Atoi(vs[1]))
	}
	return
}

func GuessTarget() (distro string, version Version) {
	targets := map[string]func() string{
		`openwrt`: guessOpenWRT,
		`ubuntu`:  guessUbuntu,
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

func guessOpenWRT() (version string) {
	data, err := os.ReadFile(`/etc/openwrt_release`)
	if err != nil {
		return
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		parts := strings.SplitN(line, `=`, 2)
		if len(parts) == 2 {
			switch parts[0] {
			case `DISTRIB_RELEASE`:
				version = parts[1]
				version = version[1 : len(version)-1]
				return
			}
		}
	}

	return
}

func guessUbuntu() (version string) {
	data, err := os.ReadFile(`/etc/issue.net`)
	if err != nil {
		return
	}

	parts := strings.Fields(string(data))
	if len(parts) == 2 && parts[0] == `Ubuntu` {
		return parts[1]
	}

	return
}
