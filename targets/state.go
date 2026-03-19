package targets

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/shell"
	"github.com/movsb/gun/pkg/tables"
	"github.com/movsb/gun/pkg/utils"
)

type State struct {
	// 具体的 iptables 命令名。
	// 因为可能是 legacy 版本的 iptables，被 ntf 取代后改名了。
	Ip4tables string
	Ip6tables string

	// 用户组编号。
	// 自动创建，总是存在。
	OutputsGroupID uint32
	DNSGroupID     uint32
	// 非主进程运行默认的用户编号（nobody）。
	// 如果获取失败，则为 0（root）。
	NobodyID uint32
	// 如果主机原本就有DNS服务器...
	// 大于0时有效，且此时使用127.0.0.1:53作为上游。
	OriginalDNSServerGroupID uint32

	ChinaDNS  string
	BannedDNS string

	chinaDomains   *rules.File
	bannedDomains  *rules.File
	ignoredUserTxt *rules.File
	bannedUserTxt  *rules.File
	chinaRoutes    *rules.File
	blockedDomains *rules.File

	extraBannedIPs  *rules.File
	extraIgnoredIPs *rules.File
}

func (s *State) addIgnoredIPs(ips []string) {
	for _, ip := range ips {
		switch {
		case strings.Contains(ip, `:`):
			s.extraIgnoredIPs.IPv6 = append(s.extraIgnoredIPs.IPv6, ip)
		default:
			s.extraIgnoredIPs.IPv4 = append(s.extraIgnoredIPs.IPv4, ip)
		}
	}
}
func (s *State) addBannedIPs(ips []string) {
	for _, ip := range ips {
		switch {
		case strings.Contains(ip, `:`):
			s.extraBannedIPs.IPv6 = append(s.extraBannedIPs.IPv6, ip)
		default:
			s.extraBannedIPs.IPv4 = append(s.extraBannedIPs.IPv4, ip)
		}
	}
}

func (s *State) SetDNSUpstreams(china string, banned string) {
	if china != `` {
		s.ChinaDNS = china
	} else if s.OriginalDNSServerGroupID > 0 {
		s.ChinaDNS = `127.0.0.1`
	} else {
		s.ChinaDNS = `223.5.5.5`
	}
	s.addIgnoredIPs([]string{s.ChinaDNS})

	if banned != `` {
		s.BannedDNS = banned
	} else {
		s.BannedDNS = `8.8.8.8`
	}
	s.addBannedIPs([]string{s.BannedDNS})
}

func (s *State) createTempFile(name string, write func(w io.Writer)) string {
	tmp := utils.Must1(os.Create(filepath.Join(os.TempDir(), name)))
	defer tmp.Close()
	write(tmp)
	return tmp.Name()
}

func (s *State) ChinaDomainsFile() string {
	return s.createTempFile(`china_domains.txt`, func(w io.Writer) {
		if s.chinaDomains != nil {
			for _, d := range s.chinaDomains.Domains {
				utils.Must1(fmt.Fprintln(w, d))
			}
		}
		if s.ignoredUserTxt != nil {
			for _, d := range s.ignoredUserTxt.Domains {
				utils.Must1(fmt.Fprintln(w, d))
			}
		}
	})
}

func (s *State) BannedDomainsFile() string {
	return s.createTempFile(`banned_domains.txt`, func(w io.Writer) {
		if s.bannedDomains != nil {
			for _, d := range s.bannedDomains.Domains {
				utils.Must1(fmt.Fprintln(w, d))
			}
		}
		if s.bannedUserTxt != nil {
			for _, d := range s.bannedUserTxt.Domains {
				utils.Must1(fmt.Fprintln(w, d))
			}
		}
	})
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
func (s *State) BlockedDomainsFile() string {
	return s.createTempFile(`blocked_domains.txt`, func(w io.Writer) {
		utils.Must1(fmt.Fprintln(w, strings.Join(s.blockedDomains.Domains, "\n")))
	})
}
func (s *State) ChinaRoutesFile() string {
	return s.createTempFile(`china_routes.txt`, func(w io.Writer) {
		chinaRoutes := []string{}
		chinaRoutes = append(chinaRoutes, s.White4()...)
		chinaRoutes = append(chinaRoutes, s.White6()...)
		utils.Must1(fmt.Fprintln(w, strings.Join(chinaRoutes, "\n")))
	})
}

func CheckCommands() {
	ip4 := findIPTables(true)
	ip6 := findIPTables(false)

	for _, name := range []string{`sysctl`, `ip`, `ipset`} {
		cmdMustExist(name)
	}
	for _, mod := range []string{`conntrack`, `addrtype`} {
		if !hasIPTablesModule(ip4, mod) {
			log.Fatalf(`没有找到 iptables 模块：%s。`, mod)
		}
	}
	for _, table := range []string{`nat`} {
		if !hasIPTablesTable(ip6, table) {
			log.Panicf(`没有找到 iptables 表：%s。`, table)
		}
	}
}

func LoadStates(configDir string) *State {
	state := State{
		Ip4tables: findIPTables(true),
		Ip6tables: findIPTables(false),

		chinaDomains:   rules.Parse(filepath.Join(configDir, rules.ChinaDomainsName)),
		bannedDomains:  rules.Parse(filepath.Join(configDir, rules.GfwDomainsName)),
		chinaRoutes:    rules.Parse(filepath.Join(configDir, rules.ChinaRoutesName)),
		bannedUserTxt:  rules.Parse(filepath.Join(configDir, rules.BannedUserTxt)),
		ignoredUserTxt: rules.Parse(filepath.Join(configDir, rules.IgnoredUserTxt)),
		blockedDomains: rules.Parse(filepath.Join(configDir, rules.BlockedUserTxt)),

		extraBannedIPs:  &rules.File{},
		extraIgnoredIPs: &rules.File{},
	}

	CheckCommands()

	createGroups(tables.OutputsGroupName, tables.DNSGroupName)
	state.OutputsGroupID = GetGroupID(tables.OutputsGroupName)
	state.DNSGroupID = GetGroupID(tables.DNSGroupName)
	state.NobodyID, _ = GetUserID(`nobody`)
	if state.NobodyID == 0 {
		log.Println(`⚠️警告：没有找到 nobody 用户，外部进程将以 root 权限运行。`)
	}

	state.OriginalDNSServerGroupID = uint32(bypassOriginalDNSServer())

	return &state
}

// 自动添加用户组。
//
// groupadd 是 posix 标准命令；addgroup 是高层脚本封装。
// -f 会自动忽略已经存在的用户名（对应于非初次启动）。
func createGroups(direct, proxy string) {
	sh := shell.Bind(
		shell.WithValues(`d`, direct, `p`, proxy),
		shell.WithIgnoreErrors(`in use`, `already exists`),
	)
	_, err1 := exec.LookPath(`groupadd`)
	if err1 == nil {
		sh.Run(`groupadd -f ${d}`)
		sh.Run(`groupadd -f ${p}`)
		return
	}
	// 有可能是来自 busybox，没有 -f 选项。
	_, err2 := exec.LookPath(`addgroup`)
	if err2 == nil {
		sh.Run(`addgroup ${d}`)
		sh.Run(`addgroup ${p}`)
		return
	}
	log.Fatalf(`未能创建用户组：%v`, errors.Join(err1, err2))
}

func GetGroupID(name string) uint32 {
	group, err := user.LookupGroup(name)
	if err != nil {
		log.Fatalf(`无法取得用户组编号：%s: %v`, name, err)
	}
	n := utils.Must1(strconv.Atoi(group.Gid))
	return uint32(n)
}

func GetUserID(name string) (uint32, error) {
	user, err := user.Lookup(`nobody`)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(user.Uid)
	return uint32(n), err
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
		log.Fatalf(`找不到 %s 命令。`, newName)
	}

	var output bytes.Buffer
	shell.Run(`${newName} -h`, shell.WithValues(`newName`, newName), shell.WithCombined(&output))
	if strings.Contains(output.String(), `(nf_tables)`) {
		log.Fatalf(`找到了 %s 命令，但其是 nftables。请安装 %s。`, newName, oldName)
	}

	return newName
}

func cmdMustExist(name string) {
	_, err := exec.LookPath(name)
	if err != nil {
		log.Fatalln(name, err)
	}
}

func hasIPTablesModule(iptables string, module string) bool {
	var output bytes.Buffer
	shell.Run(fmt.Sprintf(`%s -m %s -h`, iptables, module), shell.WithCombined(&output), shell.WithIgnoreErrors())
	if strings.Contains(output.String(), `Couldn't load match`) {
		return false
	}
	if strings.Contains(output.String(), `Usage:`) {
		return true
	}
	if strings.Contains(output.String(), `getsockopt failed strangely: Operation not permitted`) {
		log.Fatalln(`权限不够。如果是在容器中，请给容器添加 NET_ADMIN 权限。`)
	}
	log.Fatalln(iptables, module, output.String())
	return false
}

func hasIPTablesTable(iptables string, table string) bool {
	var output bytes.Buffer
	shell.Run(fmt.Sprintf(`%s -t %s -S`, iptables, table), shell.WithCombined(&output), shell.WithIgnoreErrors())
	return !strings.Contains(output.String(), `Table does not exist`)
}

// 尽量不使用外部工具。
// 找到原生DNS服务器的用户组。
// 找到监听udp:53的inode，根据inode查找pid，再查gid。
func bypassOriginalDNSServer() uint {
	udpFile, err := os.Open(`/proc/net/udp`)
	if err != nil {
		log.Println(err)
		return 0
	}
	defer udpFile.Close()

	scanner := bufio.NewScanner(udpFile)
	var inode string
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 10 && strings.HasSuffix(fields[1], `:0035`) {
			inode = fields[9]
			break
		}
	}
	if inode == `` {
		return 0
	}

	socket := fmt.Sprintf(`socket:[%s]`, inode)
	var pidFound int
	fds, _ := filepath.Glob(`/proc/[0-9]*/fd/*`)
	for _, fd := range fds {
		target, _ := os.Readlink(fd)
		if target == socket {
			pidFound, _ = strconv.Atoi(strings.Split(fd, `/`)[2])
			break
		}
	}
	if pidFound <= 0 {
		return 0
	}

	statusFile, err := os.Open(fmt.Sprintf(`/proc/%d/status`, pidFound))
	if err != nil {
		log.Println(err)
		return 0
	}
	defer statusFile.Close()

	egid := 0
	scanner = bufio.NewScanner(statusFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 5 && fields[0] == `Gid:` {
			// Gid: real effective saved filesystem
			egid, _ = strconv.Atoi(fields[2])
			break
		}
	}

	return uint(egid)
}
