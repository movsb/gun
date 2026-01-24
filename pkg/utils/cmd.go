package utils

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
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
		log.Fatalf(`环境变量未找到：%s`, name)
	}
	return v
}

func MustGetEnvInt(name string) int {
	v := MustGetEnvString(name)
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf(`无效数字：%s`, v)
	}
	return n
}
