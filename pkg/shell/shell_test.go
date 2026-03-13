package shell

import (
	"bytes"
	"testing"
)

func TestShell(t *testing.T) {
	var b bytes.Buffer
	Run(`echo 123`, WithCombined(&b))
	if b.String() != "123\n" {
		t.Fatal(`not equal`)
	}
}

func TestErrorMatcher(t *testing.T) {
	m := _ErrorMatcher{
		errors: []string{`second line`},
	}

	expect := func(b bool) {
		if m.matched != b {
			panic(`not match`)
		}
	}

	m.Write([]byte("first line\n"))
	expect(false)

	m.Write([]byte(`second `))
	expect(false)
	m.Write([]byte("line\n"))
	expect(true)
}
