package shell

import (
	"bytes"
	"reflect"
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

func TestParse(t *testing.T) {
	args, err := parse(`ls 1 ${a} 3`, map[string]any{`a`: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{`ls`, `1`, `2`, `3`}) {
		t.Fatal(`not equal`)
	}

	args, err = parse(`ls 1${a}3`, map[string]any{`a`: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{`ls`, `123`}) {
		t.Fatal(`not equal`)
	}

	args, err = parse(`ls 1 ${a} 3`, map[string]any{`a`: ``})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{`ls`, `1`, ``, `3`}) {
		t.Fatal(`not equal`)
	}
}
