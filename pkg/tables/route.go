package tables

import "github.com/movsb/gun/pkg/shell"

func CreateIPRoute(family Family) {
	sh := shell.Bind(shell.WithValues(
		`family`, family,
		`table`, TPROXY_TABLE,
		`mark`, TPROXY_MARK,
	))
	sh.Run(`ip -${family} route add local default dev lo table ${table}`)
	sh.Run(`ip -${family} rule add fwmark ${mark} table ${table}`)
}

func DeleteIPRoute(family Family) {
	sh := shell.Bind(
		shell.WithValues(
			`family`, family,
			`table`, TPROXY_TABLE,
			`mark`, TPROXY_MARK,
		),
		shell.WithIgnoreErrors(
			`No such file or directory`,
			`No such process`,
			`table does not exist`,
		),
	)
	sh.Run(`ip -${family} rule  del   table ${table}`)
	sh.Run(`ip -${family} route flush table ${table}`)
}
