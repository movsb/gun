package shell_test

import (
	"bytes"
	"testing"

	"github.com/movsb/gun/pkg/shell"
)

func TestShell(t *testing.T) {
	var b bytes.Buffer
	shell.Run(`echo 123`, shell.WithCombined(&b))
	if b.String() != "123\n" {
		t.Fatal(`not equal`)
	}
}
