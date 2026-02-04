package shell_test

import (
	"testing"

	"github.com/movsb/gun/pkg/shell"
)

func TestShell(t *testing.T) {
	shell.Run(`echo ${a} \
	233`, shell.WithValues(`a`, `/`))
}
