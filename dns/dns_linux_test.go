package dns

import (
	"slices"
	"testing"
)

func TestSplit(t *testing.T) {
	want := []string{`xxx.yyy.example.com`, `yyy.example.com`, `example.com`, `com`}
	got := []string{}

	for d := range split(`xxx.yyy.example.com.`) {
		got = append(got, d)
	}
	if !slices.Equal(want, got) {
		t.Fatal(`不相等：`, want, got)
	}
}
