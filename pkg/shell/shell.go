package shell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/movsb/gun/pkg/utils"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

type Option func(*Command)

type Command struct {
	cmd            *exec.Cmd
	ctx            context.Context
	dir            string
	env            map[string]any
	args           []string
	gid            uint32
	ignoreErrors   bool
	errors         []string
	silent         bool
	stdin          io.Reader
	stdout         io.Writer
	stderr         io.Writer
	interpolations map[string]any
	process        **os.Process
}

func (c *Command) Run() string {
	// 拷贝一份输出以判断错误。
	// TODO: 程序退出之前内容一直在内存中。
	var b bytes.Buffer
	if c.stdout == nil {
		c.cmd.Stdout = &b
	} else {
		c.cmd.Stdout = io.MultiWriter(c.cmd.Stdout, &b)
	}
	if c.stderr == nil {
		c.cmd.Stderr = &b
	} else {
		c.cmd.Stderr = io.MultiWriter(c.cmd.Stderr, &b)
	}

	if err := c.cmd.Start(); err != nil {
		// 这个错误暂时没像下面那样处理。
		panic(err)
	}

	if c.process != nil {
		*c.process = c.cmd.Process
	}

	err := c.cmd.Wait()

	output := b.String()

	if err != nil {
		if c.ignoreErrors {
			return output
		}
		for _, expect := range c.errors {
			if strings.Contains(output, expect) {
				return output
			}
			if strings.Contains(err.Error(), expect) {
				return output
			}
		}
		panic(fmt.Errorf("unexpected error: %w\n\n%s\n\n%s", err, c.cmd.String(), output))
	}

	if !c.silent && len(output) > 0 {
		_, file, no, _ := runtime.Caller(1)
		if strings.Contains(file, `shell.go`) {
			_, file, no, _ = runtime.Caller(2)
		}
		log.Printf("%s:%d\n", file, no)
		fmt.Print(output)
		if output[len(output)-1] != '\n' {
			fmt.Println()
		}
	}

	return output
}

type _Bound struct {
	options []Option
}

func Bind(options ...Option) _Bound {
	return _Bound{options: options}
}

func (b _Bound) Run(cmdline string, options ...Option) string {
	return Run(cmdline, append(b.options, options...)...)
}

// 运行并等待退出。
//
// 退出有多方面原因：
//
//   - 可能是进程正常退出。
//   - 可能是 ctx 到期被取消。
//
// 但是：虽然 exec.Command 声称 ctx 到期后 process 会被 kill，
// 但是 kill 不一定会成功。
func Run(cmdline string, options ...Option) string {
	return Shell(cmdline, options...).Run()
}

func Shell(cmdline string, options ...Option) *Command {
	c := &Command{
		ctx:            context.Background(),
		interpolations: map[string]any{},
		env:            map[string]any{},
	}
	for _, o := range options {
		o(c)
	}

	args, err := shell(cmdline, c.interpolations)
	if err != nil {
		panic(err)
	}

	c.cmd = exec.CommandContext(c.ctx, args[0], args[1:]...)
	c.cmd.Args = append(c.cmd.Args, c.args...)

	if c.dir != `` {
		c.cmd.Dir = c.dir
	}
	if len(c.env) > 0 {
		cur := os.Environ()
		for k, v := range c.env {
			cur = append(cur, fmt.Sprintf(`%s=%v`, k, v))
		}
		c.cmd.Env = cur
	}

	if c.stdin != nil {
		c.cmd.Stdin = c.stdin
	}
	if c.stdout != nil {
		c.cmd.Stdout = c.stdout
	}
	if c.stderr != nil {
		c.cmd.Stderr = c.stderr
	}

	if c.gid > 0 {
		c.cmd.SysProcAttr = &syscall.SysProcAttr{
			// 父进程退出时强制退出。
			Pdeathsig: syscall.SIGKILL,
			Credential: &syscall.Credential{
				Gid:         c.gid,
				NoSetGroups: true,
			},
		}
	}

	return c
}

func WithEnv(k string, v any) Option {
	return func(c *Command) {
		c.env[k] = v
	}
}

// 输出进程对象。
func WithOutputProcess(process **os.Process) Option {
	return func(c *Command) {
		c.process = process
	}
}

// `${self}` == os.Args[0]
// 是否应该总是默认添加？
func WithCmdSelf() Option {
	return func(c *Command) {
		c.interpolations[`self`] = os.Args[0]
	}
}

// 以指定用户组运行进程。
func WithGID(gid uint32) Option {
	return func(c *Command) {
		c.gid = gid
	}
}

func WithStdin(r io.Reader) Option {
	return func(c *Command) {
		c.stdin = r
	}
}

// 设定标准输出。
//
// 即便设定为 os.Stdout，暂时也不支持伪终端特性。
func WithStdout(w io.Writer) Option {
	return func(c *Command) {
		c.stdout = w
	}
}

// 设定标准错误输出。
//
// 即便设定为 os.Stderr，暂时也不支持伪终端特性。
func WithStderr(w io.Writer) Option {
	return func(c *Command) {
		c.stderr = w
	}
}

// 静音命令输出。
//
// 但是Run()的返回值仍然会包含结果。
func WithSilent() Option {
	return func(c *Command) {
		c.silent = true
	}
}

func WithDir(dir string) Option {
	return func(c *Command) {
		c.dir = dir
	}
}

// 解析 cmdline 之后再追加到其后。
func WithArgs(args ...string) Option {
	return func(c *Command) {
		c.args = append(c.args, args...)
	}
}

func WithMaps(kv map[string]any) Option {
	pairs := []any{}
	for k, v := range kv {
		pairs = append(pairs, k, v)
	}
	return WithValues(pairs...)
}

// pairs: [string, any, string, any, ...]
func WithValues(pairs ...any) Option {
	if len(pairs)%2 != 0 {
		panic(`invalid interpolations values`)
	}
	return func(c *Command) {
		for i := 0; i < len(pairs)/2; i++ {
			k := pairs[i*2+0].(string)
			v := pairs[i*2+1]
			c.interpolations[k] = v
		}
	}
}
func WithContext(ctx context.Context) Option {
	return func(c *Command) {
		c.ctx = ctx
	}
}

// 忽略包含指定字符串的错误。
//
// 错误可以来自：标准输出、标准错误输出、命令执行返回的错误（err）。
//
// 如果不带参数，会忽略命令执行时返回的错误（err）。
func WithIgnoreErrors(contains ...string) Option {
	return func(c *Command) {
		c.errors = append(c.errors, contains...)
		c.ignoreErrors = len(c.errors) <= 0
	}
}

func shell(cmdline string, interpolations map[string]any) (args []string, outErr error) {
	defer utils.CatchAsError(&outErr)

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(cmdline), ``)
	if err != nil {
		return nil, fmt.Errorf(`failed to intermediate interpolation string: %s: %w`, cmdline, err)
	}
	if len(file.Stmts) > 1 {
		return nil, fmt.Errorf(`single command only`)
	}

	stmt0 := file.Stmts[0]
	noBackground(stmt0)
	noNegated(stmt0)
	noRedirects(stmt0)

	switch typed := stmt0.Cmd.(type) {
	default:
		panic(`unsupported command type`)
	case *syntax.CallExpr:
		return call(typed, interpolations)
	}
}

func call(expr *syntax.CallExpr, interpolations map[string]any) ([]string, error) {
	noAssigns(expr)

	env := _ReplacedInterpolationExpander{Known: interpolations}

	command, err := expandWord(expr.Args[0], env)
	if err != nil {
		return nil, err
	}

	var args []string
	for _, arg := range expr.Args[1:] {
		expanded, err := expandWord(arg, env)
		if err != nil {
			return nil, err
		}
		args = append(args, expanded)
	}

	return append([]string{command}, args...), nil
}

func expandWord(word *syntax.Word, env _ReplacedInterpolationExpander) (string, error) {
	if lit := word.Lit(); lit != `` {
		return lit, nil
	}
	argName, err := expand.Literal(&expand.Config{
		Env:     env,
		NoUnset: true,
	}, word)
	if err != nil {
		return ``, err
	}
	value := env.ValueOf(argName)
	if value == nil {
		return ``, fmt.Errorf(`unknown argument: %s`, argName)
	}
	switch {
	case utils.IsPOD(value):
		return fmt.Sprint(value), nil
	default:
		return ``, fmt.Errorf(`unknown value type: %v(%v)`, value, reflect.TypeOf(value))
	}
}

type _ReplacedInterpolationExpander struct {
	Known map[string]any
}

func (r _ReplacedInterpolationExpander) ValueOf(name string) any {
	return r.unwrapValues(name)
}

func (r _ReplacedInterpolationExpander) Get(name string) expand.Variable {
	if _, ok := r.Known[name]; !ok {
		return expand.Variable{}
	}
	return expand.Variable{
		Kind: expand.String,
		Set:  true,
		Str:  r.wrap(name),
	}
}
func (r _ReplacedInterpolationExpander) wrap(name string) string {
	return fmt.Sprintf(`__jg_%s_jg__`, name)
}

var reSplitWrapped = regexp.MustCompile(`(?U:__jg_.*_jg__)`)

func (r _ReplacedInterpolationExpander) unwrapValues(name string) any {
	// 如果替换后不为空，证明有其它字面字符，则参数值必须为字符串。
	n := 0
	empty := reSplitWrapped.ReplaceAllStringFunc(name, func(s string) string {
		n++
		return ``
	})
	if n == 0 {
		return name
	}

	// 单值时可以为任意类型。
	if n == 1 && empty == `` {
		var onlyValue any
		reSplitWrapped.ReplaceAllStringFunc(name, func(s string) string {
			s = strings.TrimPrefix(s, `__jg_`)
			s = strings.TrimSuffix(s, `_jg__`)
			v, ok := r.Known[s]
			if !ok {
				panic(fmt.Errorf(`no such value: %s`, s))
			}
			onlyValue = v
			return ``
		})
		return onlyValue
	}

	// 其它情况必须为基本类型。
	return reSplitWrapped.ReplaceAllStringFunc(name, func(s string) string {
		s = strings.TrimPrefix(s, `__jg_`)
		s = strings.TrimSuffix(s, `_jg__`)
		v, ok := r.Known[s]
		if !ok {
			panic(fmt.Errorf(`no such value: %s`, s))
		}
		switch {
		case utils.IsPOD(v):
			return fmt.Sprint(v)
		default:
			panic(fmt.Errorf(`unknown value type: %v(%v)`, v, reflect.TypeOf(v)))
		}
	})
}

func (r _ReplacedInterpolationExpander) Each(predicate func(name string, vr expand.Variable) bool) {
	for k := range r.Known {
		if !predicate(k, expand.Variable{
			Kind: expand.String,
			Set:  true,
			Str:  r.wrap(k),
		}) {
			break
		}
	}
}

func noBackground(stmt *syntax.Stmt) {
	if stmt.Background {
		panic(`cannot run in background`)
	}
}
func noNegated(stmt *syntax.Stmt) {
	if stmt.Negated {
		panic(`cannot test negated`)
	}
}
func noAssigns(call *syntax.CallExpr) {
	if len(call.Assigns) > 0 {
		panic(`no assigns allowed`)
	}
}
func noRedirects(stmt *syntax.Stmt) {
	if len(stmt.Redirs) > 0 {
		panic(`no redirects allowed`)
	}
}
