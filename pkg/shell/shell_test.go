package shell_test

import (
	"testing"

	"github.com/movsb/gun/pkg/shell"
)

func TestShell(t *testing.T) {
	cmd := shell.Shell(`ls ${a}`, shell.WithValues(`a`, `/`))
	cmd.Run()
}
