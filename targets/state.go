package targets

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/utils"
)

type State struct {
	// 具体的 iptables 命令名。
	// 因为可能是 legacy 版本的 iptables，被 ntf 取代后改名了。
	Ip4tables string
	Ip6tables string

	// 用户组编号。
	// 自动创建，总是存在。
	ProxyGroupID  uint32
	DirectGroupID uint32

	chinaDomains   *rules.File
	bannedDomains  *rules.File
	ignoredUserTxt *rules.File
	bannedUserTxt  *rules.File
	chinaRoutes    *rules.File

	extraBannedIPs  *rules.File
	extraIgnoredIPs *rules.File
}

func (s *State) AddIgnoredIPs(ips []string) {
	for _, ip := range ips {
		switch {
		case strings.Contains(ip, `:`):
			s.extraIgnoredIPs.IPv6 = append(s.extraIgnoredIPs.IPv6, ip)
		default:
			s.extraIgnoredIPs.IPv4 = append(s.extraIgnoredIPs.IPv4, ip)
		}
	}
}
func (s *State) AddBannedIPs(ips []string) {
	for _, ip := range ips {
		switch {
		case strings.Contains(ip, `:`):
			s.extraBannedIPs.IPv6 = append(s.extraBannedIPs.IPv6, ip)
		default:
			s.extraBannedIPs.IPv4 = append(s.extraBannedIPs.IPv4, ip)
		}
	}
}

func (s *State) ChinaDomainsFile() string {
	tmp := utils.Must1(os.CreateTemp(``, ``))
	defer tmp.Close()

	if s.chinaDomains != nil {
		for _, d := range s.chinaDomains.Domains {
			utils.Must1(fmt.Fprintln(tmp, d))
		}
	}
	if s.ignoredUserTxt != nil {
		for _, d := range s.ignoredUserTxt.Domains {
			utils.Must1(fmt.Fprintln(tmp, d))
		}
	}
	return tmp.Name()
}

func (s *State) BannedDomainsFile() string {
	tmp := utils.Must1(os.CreateTemp(``, ``))
	defer tmp.Close()

	if s.bannedDomains != nil {
		for _, d := range s.bannedDomains.Domains {
			utils.Must1(fmt.Fprintln(tmp, d))
		}
	}
	if s.bannedUserTxt != nil {
		for _, d := range s.bannedUserTxt.Domains {
			utils.Must1(fmt.Fprintln(tmp, d))
		}
	}
	return tmp.Name()
}

func (s *State) White4() (ips []string) {
	ips = append(ips, s.ignoredUserTxt.IPv4...)
	ips = append(ips, s.chinaRoutes.IPv4...)
	ips = append(ips, s.extraIgnoredIPs.IPv4...)
	return
}
func (s *State) White6() (ips []string) {
	ips = append(ips, s.ignoredUserTxt.IPv6...)
	ips = append(ips, s.chinaRoutes.IPv6...)
	ips = append(ips, s.extraIgnoredIPs.IPv6...)
	return
}
func (s *State) Black4() (ips []string) {
	ips = append(ips, s.bannedUserTxt.IPv4...)
	ips = append(ips, s.extraBannedIPs.IPv4...)
	return
}
func (s *State) Black6() (ips []string) {
	ips = append(ips, s.bannedUserTxt.IPv6...)
	ips = append(ips, s.extraBannedIPs.IPv6...)
	return
}

func LoadStates(directGroupName, proxyGroupName string) *State {
	state := State{
		Ip4tables: findIPTables(true),
		Ip6tables: findIPTables(false),

		chinaDomains:   rules.Parse(rules.ChinaDomainsName),
		bannedDomains:  rules.Parse(rules.GfwDomainsName),
		chinaRoutes:    rules.Parse(rules.ChinaRoutesName),
		bannedUserTxt:  rules.Parse(rules.BannedUserTxt),
		ignoredUserTxt: rules.Parse(rules.IgnoredUserTxt),

		extraBannedIPs:  &rules.File{},
		extraIgnoredIPs: &rules.File{},
	}

	for _, name := range []string{`sysctl`, `ip`, `ipset`, `groupadd`} {
		cmdMustExist(name)
	}
	for _, mod := range []string{`conntrack`, `addrtype`} {
		if !hasIPTablesModule(state.Ip4tables, mod) {
			log.Panicf(`没有找到 iptables 模块：%s。`, mod)
		}
	}
	for _, table := range []string{`nat`} {
		if !hasIPTablesTable(state.Ip4tables, table) {
			log.Panicf(`没有找到 iptables 表：%s。`, table)
		}
	}

	// 自动添加用户组。
	// -f 会自动忽略已经存在的用户名（对应于非初次启动）。
	shell.Run(`groupadd -f ${name}`, shell.WithValues(`name`, directGroupName))
	shell.Run(`groupadd -f ${name}`, shell.WithValues(`name`, proxyGroupName))
	state.DirectGroupID = GetGroupID(directGroupName)
	state.ProxyGroupID = GetGroupID(proxyGroupName)

	return &state
}

func GetGroupID(name string) uint32 {
	group, err := user.LookupGroup(name)
	if err != nil {
		log.Panicf(`无法取得用户组编号：%s: %v`, name, err)
	}
	n := utils.Must1(strconv.Atoi(group.Gid))
	return uint32(n)
}

// 返回 iptables, ip6tables 的真正命令名。
func FindIPTablesCommands() (string, string) {
	return findIPTables(true), findIPTables(false)
}

// 有 legacy 就先用，没有的话判断是不是 ntf。
func findIPTables(v4Orv6 bool) string {
	oldName := utils.IIF(v4Orv6, `iptables-legacy`, `ip6tables-legacy`)
	newName := utils.IIF(v4Orv6, `iptables`, `ip6tables`)

	_, err := exec.LookPath(oldName)
	if err == nil {
		return oldName
	}

	_, err = exec.LookPath(newName)
	if err != nil {
		log.Panicf(`找不到 %s 命令。`, newName)
	}

	output := shell.Run(newName, shell.WithSilent())
	if strings.Contains(output, `(nf_tables)`) {
		log.Panicf(`找到了 %s 命令，但其是 nftables。请安装 %s。`, newName, oldName)
	}

	return newName
}

func cmdMustExist(name string) {
	_, err := exec.LookPath(name)
	if err != nil {
		log.Panicf(name, err)
	}
}

func hasIPTablesModule(iptables string, module string) bool {
	output := shell.Run(fmt.Sprintf(`%s -m %s -h`, iptables, module), shell.WithSilent(), shell.WithIgnoreErrors())
	if strings.Contains(output, `Couldn't load match`) {
		return false
	}
	if strings.Contains(output, `Usage:`) {
		return true
	}
	panic(output)
}

func hasIPTablesTable(iptables string, table string) bool {
	output := shell.Run(fmt.Sprintf(`%s -t %s -S`, iptables, table), shell.WithSilent(), shell.WithIgnoreErrors())
	if strings.Contains(output, `Table does not exist`) {
		return false
	}
	return true
}
