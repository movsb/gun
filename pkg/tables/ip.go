package tables

import (
	"strings"

	"github.com/movsb/gun/pkg/shell"
)

const (
	GUN_PREFIX_     = `GUN_`
	GUN_PREROUTING  = `GUN_PREROUTING`
	GUN_OUTPUT      = `GUN_OUTPUT`
	GUN_POSTROUTING = `GUN_POSTROUTING`
	GUN_RULE        = `GUN_RULE`
	GUN_QUIC        = `GUN_QUIC`
)

var (
	chainNames = shell.WithMaps(map[string]any{
		`prerouting`:  GUN_PREROUTING,
		`output`:      GUN_OUTPUT,
		`postrouting`: GUN_POSTROUTING,
		`rule`:        GUN_RULE,
		`quic`:        GUN_QUIC,
	})
)

// 创建需要的链接。
//
// cmd：iptables/ip6tables{-legacy}
//
// 存在会出错。
func CreateChains(cmd string) {
	_addChains(cmd)
	_addEntrypoints(cmd)
}

func _addChains(cmd string) {
	sh := shell.Bind(shell.WithValues(`cmd`, cmd), chainNames)

	sh.Run(`${cmd} -t mangle -N ${prerouting}`)
	sh.Run(`${cmd} -t mangle -N ${output}`)
	sh.Run(`${cmd} -t mangle -N ${rule}`)
	sh.Run(`${cmd} -t mangle -N ${quic}`)

	sh.Run(`${cmd} -t nat -N ${prerouting}`)
	sh.Run(`${cmd} -t nat -N ${output}`)
	sh.Run(`${cmd} -t nat -N ${postrouting}`)
}

func _addEntrypoints(cmd string) {
	sh := shell.Bind(shell.WithValues(`cmd`, cmd), chainNames)

	sh.Run(`${cmd} -t mangle -A PREROUTING  -j ${prerouting}`)
	sh.Run(`${cmd} -t mangle -A OUTPUT      -j ${output}`)

	sh.Run(`${cmd} -t nat    -A PREROUTING  -j ${prerouting}`)
	sh.Run(`${cmd} -t nat    -A OUTPUT      -j ${output}`)
	sh.Run(`${cmd} -t nat    -A POSTROUTING -j ${postrouting}`)
}

// 彻底删除创建的链。
//
//   - 不存在的链不会报错。
//   - 会同时清空IPv4和IPv6，避免配置修改残留。
func DeleteChains(cmd string) {
	// 先删除系统表对我创建的这些表的引用。
	_deleteEntrypoints(cmd)
	// 然后清空规则、删除链。
	_flushChains(cmd)
}

func _deleteEntrypoints(cmd string) {
	sh := shell.Bind(
		shell.WithValues(`cmd`, cmd), chainNames,
		shell.WithIgnoreErrors(
			`Couldn't load target`,
			`No chain/target/match by that name`,
		),
	)

	sh.Run(`${cmd} -t mangle -D PREROUTING -j ${prerouting}`)
	sh.Run(`${cmd} -t mangle -D OUTPUT     -j ${output}`)

	sh.Run(`${cmd} -t nat -D PREROUTING  -j ${prerouting}`)
	sh.Run(`${cmd} -t nat -D OUTPUT      -j ${output}`)
	sh.Run(`${cmd} -t nat -D POSTROUTING -j ${postrouting}`)
}

func _flushChains(cmd string) {
	sh := shell.Bind(shell.WithValues(`cmd`, cmd), shell.WithSilent())
	for _, table := range []string{`mangle`, `nat`} {
		output := sh.Run(`${cmd} -t ${table} -S`, shell.WithValues(`table`, table))
		for p := range strings.SplitSeq(output, "\n") {
			if !strings.HasPrefix(p, `-N `+GUN_PREFIX_) {
				continue
			}

			name := strings.Fields(p)[1]
			values := shell.WithValues(`cmd`, cmd, `table`, table, `name`, name)

			// 需要先清空再删除，否则会报错：iptables: Directory not empty.
			shell.Run(`${cmd} -t ${table} -F ${name}`, values)
			shell.Run(`${cmd} -t ${table} -X ${name}`, values)
		}
	}
}
