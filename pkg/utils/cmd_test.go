package utils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestLoggerTailLines(t *testing.T) {
	logger := NewLogger(0, 0)
	fmt.Fprint(logger, "one\n")
	fmt.Fprint(logger, "two\n")
	fmt.Fprint(logger, "three\n")

	logger.lock.Lock()
	lines, nextID := logger.tailLines(2)
	logger.lock.Unlock()

	if got := string(joinLogLines(lines)); got != "two\nthree\n" {
		t.Fatalf("tail = %q", got)
	}
	if nextID != 3 {
		t.Fatalf("nextID = %d", nextID)
	}
}

func TestLoggerTailAllLines(t *testing.T) {
	logger := NewLogger(0, 0)
	fmt.Fprint(logger, "one\n")
	fmt.Fprint(logger, "two\n")
	fmt.Fprint(logger, "three\n")

	logger.lock.Lock()
	lines, nextID := logger.tailLines(-1)
	logger.lock.Unlock()

	if got := string(joinLogLines(lines)); got != "one\ntwo\nthree\n" {
		t.Fatalf("tail = %q", got)
	}
	if nextID != 3 {
		t.Fatalf("nextID = %d", nextID)
	}
}

func TestLoggerKeepsPartialLine(t *testing.T) {
	logger := NewLogger(0, 0)
	fmt.Fprint(logger, "one\n")
	fmt.Fprint(logger, "par")
	fmt.Fprint(logger, "tial\n")

	logger.lock.Lock()
	lines, _ := logger.tailLines(2)
	logger.lock.Unlock()

	if got := string(joinLogLines(lines)); got != "one\npartial\n" {
		t.Fatalf("tail = %q", got)
	}
}

func TestLoggerHTTPLogsTailAndFollow(t *testing.T) {
	logger := NewLogger(0, 0)
	fmt.Fprint(logger, "one\n")
	fmt.Fprint(logger, "two\n")
	fmt.Fprint(logger, "three\n")

	socket := filepath.Join(t.TempDir(), "log.sock")
	mux := http.NewServeMux()
	go func() {
		lis := Must1(net.Listen(`unix`, socket))
		defer lis.Close()
		http.Serve(lis, mux)
	}()
	go logger.Serve(mux)
	waitUnixSocket(t, socket)

	client := unixHTTPClient(socket)
	rsp, err := client.Get("http://gun/v1/logs?tail=2")
	if err != nil {
		t.Fatalf("get logs: %v", err)
	}
	defer rsp.Body.Close()

	fmt.Fprint(logger, "four\n")

	buf := make([]byte, len("two\nthree\nfour\n"))
	if _, err := io.ReadFull(rsp.Body, buf); err != nil {
		t.Fatalf("read logs: %v", err)
	}
	if string(buf) != "two\nthree\nfour\n" {
		t.Fatalf("logs = %q", string(buf))
	}
}

func joinLogLines(lines [][]byte) []byte {
	var out []byte
	for _, line := range lines {
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
}

func unixHTTPClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func waitUnixSocket(t *testing.T, socket string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socket)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatalf("timed out waiting for %s", socket)
}
