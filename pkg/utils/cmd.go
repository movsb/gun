package utils

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func CatchAsError(err *error) {
	if er := recover(); er != nil {
		if er2, ok := er.(error); ok {
			*err = er2
			return
		}
		*err = fmt.Errorf(`%v`, er)
	}
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

func Map[T any, S []E, E any](s S, mapper func(e E) T) []T {
	t := make([]T, 0, len(s))
	for _, a := range s {
		t = append(t, mapper(a))
	}
	return t
}

func IIF[Any any](cond bool, first, second Any) Any {
	if cond {
		return first
	}
	return second
}

// 普通文件存在？
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
		return false
	}
	if info.Mode().IsRegular() {
		return true
	}
	panic(`路径存在，但不是普通文件。`)
}

func IsPOD(v any) bool {
	switch reflect.TypeOf(v).Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64,
		reflect.String:
		return true
	default:
		return false
	}
}

func MustGetEnvString(name string) string {
	v, found := os.LookupEnv(name)
	if !found {
		panic(fmt.Sprintf(`环境变量未找到：%s`, name))
	}
	return v
}

func MustGetEnvInt(name string) int {
	v := MustGetEnvString(name)
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf(`无效数字：%s`, v))
	}
	return n
}

func MustGetEnvBool(name string) bool {
	v := MustGetEnvString(name)
	switch v {
	case `true`:
		return true
	case `false`:
		return false
	default:
		panic(fmt.Sprintf(`无效布尔值：%s`, v))
	}
}

// 杀掉当前进程的所有任务子进程。
//
// 任务子进程是通过可执行文件的绝对路径来判断的，
// 而非系统内的父子进程关系。
//
// 增加：外部进程是通过设置 GUN_CHILD=1 来启动的。它们
// 也应该被杀掉。（因为手动执行 stop 命令时很难判断父子关系，
// 且与主可执行文件路径无关。）
func KillChildren() {
	var childProcesses []int

	// 收集本进程的所有子进程（同二进制文件）。
	self := Must1(os.Readlink(`/proc/self/exe`))
	for _, link := range Must1(filepath.Glob(`/proc/[0-9]*/exe`)) {
		to, _ := os.Readlink(link)
		if to != self {
			continue
		}
		pid := Must1(strconv.Atoi(strings.Split(link, "/")[2]))
		if pid == os.Getpid() {
			continue
		}
		childProcesses = append(childProcesses, pid)
	}

	// 收集本进程启动的所有外部进程（不同二进制文件）。
	for _, path := range Must1(filepath.Glob(`/proc/[0-9]*/environ`)) {
		environ, _ := os.ReadFile(path)
		list := strings.SplitSeq(string(environ), "\x00")
		for line := range list {
			if line == `GUN_CHILD=1` {
				pid := Must1(strconv.Atoi(strings.Split(path, "/")[2]))
				childProcesses = append(childProcesses, pid)
				break
			}
		}
	}

	if len(childProcesses) <= 0 {
		return
	}

	// 先温和杀一遍。
	log.Println(`清理残留子进程中...`)
	for _, pid := range childProcesses {
		now := time.Now()
		for {
			err := syscall.Kill(pid, syscall.SIGTERM)
			if err == nil {
				break
			}
			// 进程不存在。
			if errors.Is(err, syscall.ESRCH) {
				break
			}
			if time.Since(now) > time.Second*5 {
				break
			}
			time.Sleep(time.Millisecond * 500)
		}
	}

	// 再强杀一遍。
	var failedCount int
	for _, pid := range childProcesses {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue
			}
			log.Printf(`没杀掉进程：%d: %v`, pid, err)
			failedCount++
		}
	}
	if failedCount <= 0 {
		log.Println(`子进程已全部结束。`)
	}
}

// 在流之间双向拷贝。
//
// 不会关闭流，记得主动在外面关闭。
func Stream(local, remote net.Conn) {
	// 无需关闭。
	// 一个容量就够了，其中一个读走就退出，另一个就可写。
	ch := make(chan struct{}, 1)

	go func() {
		io.Copy(local, remote)
		ch <- struct{}{}
	}()
	go func() {
		io.Copy(remote, local)
		ch <- struct{}{}
	}()

	<-ch
}

type StdConn struct{}

func (c StdConn) Read(p []byte) (int, error) {
	return os.Stdin.Read(p)
}
func (c StdConn) Write(p []byte) (int, error) {
	return os.Stdout.Write(p)
}
func (c StdConn) Close() error {
	return nil
}
func (c StdConn) LocalAddr() net.Addr {
	return nil
}
func (c StdConn) RemoteAddr() net.Addr {
	return nil
}
func (c StdConn) SetDeadline(time.Time) error {
	return nil
}
func (c StdConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c StdConn) SetWriteDeadline(time.Time) error {
	return nil
}

var _ net.Conn = &StdConn{}

type Logger struct {
	lock sync.Mutex
	cond *sync.Cond

	bytes  int
	lines  list.List
	nextID uint64

	partial []byte

	maxBytes int
	maxLines int
}

type logLine struct {
	id   uint64
	line []byte
}

func NewLogger(maxBytes, maxLines int) *Logger {
	l := &Logger{
		maxBytes: maxBytes,
		maxLines: maxLines,
	}
	l.cond = sync.NewCond(&l.lock)
	return l
}

func (l *Logger) CaptureStdoutStderr() error {
	return CaptureStdoutStderr(l)
}

func CaptureStdoutStderr(w io.Writer) error {
	r, pipeWriter, err := os.Pipe()
	if err != nil {
		return err
	}

	if err := unix.Dup2(int(pipeWriter.Fd()), int(os.Stdout.Fd())); err != nil {
		r.Close()
		pipeWriter.Close()
		return err
	}
	if err := unix.Dup2(int(pipeWriter.Fd()), int(os.Stderr.Fd())); err != nil {
		r.Close()
		pipeWriter.Close()
		return err
	}
	pipeWriter.Close()

	go func() {
		defer r.Close()
		io.Copy(w, r)
	}()

	return nil
}

func (l *Logger) Write(p []byte) (int, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	total := len(p)
	if len(p) <= 0 {
		return 0, nil
	}

	var changed bool
	defer func() {
		l.trim()
		if changed {
			l.cond.Broadcast()
		}
	}()

	for len(p) > 0 {
		seg := bytes.IndexByte(p, '\n')
		if seg == -1 {
			l.partial = append(l.partial, p...)
			l.bytes += len(p)
			return total, nil
		}

		l.partial = append(l.partial, p[:seg]...)
		l.bytes += seg
		l.appendLine(l.partial)
		l.partial = l.partial[:0]
		p = p[seg+1:]
		changed = true
	}

	return total, nil
}

func (l *Logger) appendLine(line []byte) {
	l.lines.PushBack(logLine{
		id:   l.nextID,
		line: append([]byte(nil), line...),
	})
	l.nextID++
}

func (l *Logger) trim() {
	for l.maxBytes > 0 && l.bytes > l.maxBytes {
		if first := l.lines.Front(); first != nil {
			l.lines.Remove(first)
			l.bytes -= len(first.Value.(logLine).line)
			continue
		}
		if len(l.partial) > l.maxBytes {
			drop := len(l.partial) - l.maxBytes
			l.partial = append([]byte(nil), l.partial[drop:]...)
			l.bytes -= drop
		}
		break
	}
	for l.maxLines > 0 && l.lines.Len() > l.maxLines {
		if first := l.lines.Front(); first != nil {
			l.lines.Remove(first)
			l.bytes -= len(first.Value.(logLine).line)
		}
	}
}

func (l *Logger) Serve(mux *http.ServeMux) {
	mux.HandleFunc(`/v1/logs`, func(w http.ResponseWriter, r *http.Request) {
		tail, _ := strconv.Atoi(r.URL.Query().Get(`tail`))
		if tail < -1 {
			tail = 0
		}

		w.Header().Set(`Content-Type`, `text/plain; charset=utf-8`)
		flusher, _ := w.(http.Flusher)

		l.lock.Lock()
		lines, nextID := l.tailLines(tail)
		l.lock.Unlock()

		if !writeLogLines(w, flusher, lines) {
			return
		}

		go func() {
			<-r.Context().Done()
			l.lock.Lock()
			l.cond.Broadcast()
			l.lock.Unlock()
		}()

		for {
			l.lock.Lock()
			for r.Context().Err() == nil && !l.hasLinesSince(nextID) {
				l.cond.Wait()
			}
			if r.Context().Err() != nil {
				l.lock.Unlock()
				return
			}
			lines, nextID = l.linesSince(nextID)
			l.lock.Unlock()

			if !writeLogLines(w, flusher, lines) {
				return
			}
		}
	})
}

func (l *Logger) tailLines(tail int) ([][]byte, uint64) {
	nextID := l.nextID
	if tail == 0 {
		return nil, nextID
	}

	first := l.lines.Front()
	if tail > 0 {
		first = l.lines.Back()
		for n := 1; n < tail && first != nil && first.Prev() != nil; n++ {
			first = first.Prev()
		}
	}

	var lines [][]byte
	for e := first; e != nil; e = e.Next() {
		line := e.Value.(logLine).line
		lines = append(lines, append([]byte(nil), line...))
	}
	return lines, nextID
}

func (l *Logger) hasLinesSince(nextID uint64) bool {
	last := l.lines.Back()
	return last != nil && last.Value.(logLine).id >= nextID
}

func (l *Logger) linesSince(nextID uint64) ([][]byte, uint64) {
	var lines [][]byte
	for e := l.lines.Front(); e != nil; e = e.Next() {
		item := e.Value.(logLine)
		if item.id < nextID {
			continue
		}
		lines = append(lines, append([]byte(nil), item.line...))
		nextID = item.id + 1
	}
	return lines, nextID
}

func writeLogLines(w http.ResponseWriter, flusher http.Flusher, lines [][]byte) bool {
	for _, line := range lines {
		if _, err := w.Write(line); err != nil {
			return false
		}
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return false
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	return true
}
