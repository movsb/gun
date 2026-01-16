package iptables

import (
	"context"
	"os"
	"os/exec"
)

type IPTables struct {
	name string
}

func (t *IPTables) Execute(ctx context.Context, args ...string) error {
	args2 := append([]string{`-w`}, args...)
	cmd := exec.CommandContext(ctx, t.name, args2...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
