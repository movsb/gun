package utils

import (
	"context"
	"log"
	"os"
	"os/exec"
)

func Run(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Println(cmd.String())
	return cmd.Run()
}

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func Must1[T any](t T, err error) T {
	Must(err)
	return t
}

func MustRun(name string, args ...string) {
	Must(Run(name, args...))
}

func MustRunContext(ctx context.Context, name string, args ...string) {
	Must(Run(name, args...))
}

func CmdOutput(name string, args ...string) string {
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Stderr = os.Stderr
	log.Println(cmd.String())
	output := Must1(cmd.Output())
	return string(output)
}

func Map[T any, S []E, E any](s S, mapper func(e E) T) []T {
	t := make([]T, 0, len(s))
	for _, a := range s {
		t = append(t, mapper(a))
	}
	return t
}
