package utils

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
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

func MustGetBool(name string) bool {
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
func KillChildren() {
	self := Must1(os.Readlink(`/proc/self/exe`))

	// 收集所有子进程。
	var childProcesses []int
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

func Stream(local, remote net.Conn) {
	// 无需关闭。
	ch := make(chan struct{})

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
