package shell

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/movsb/gun/pkg/utils"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

type Option func(*_Command)

type _Command struct {
	cmd *exec.Cmd

	ctx      context.Context
	dir      string
	env      map[string]any
	args     []string
	uid, gid uint32
	detach   bool

	exitOnError    bool
	ignoreErrors   bool
	expectedErrors []string

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	interpolations map[string]any

	process **os.Process
}

func (c *_Command) Run() {
	b := _ErrorMatcher{errors: c.expectedErrors}
	var l *_LockedWriter

	func() {
		defer recover()
		if c.cmd.Stdout != nil && c.cmd.Stderr != nil && c.cmd.Stdout == c.cmd.Stderr {
			l = &_LockedWriter{w: c.cmd.Stdout}
		}
	}()

	if c.cmd.Stdout == nil {
		c.cmd.Stdout = &b
	} else {
		if l == nil {
			c.cmd.Stdout = io.MultiWriter(c.cmd.Stdout, &b)
		} else {
			c.cmd.Stdout = io.MultiWriter(l, &b)
		}
	}
	if c.cmd.Stderr == nil {
		c.cmd.Stderr = &b
	} else {
		if l == nil {
			c.cmd.Stderr = io.MultiWriter(c.cmd.Stderr, &b)
		} else {
			c.cmd.Stderr = io.MultiWriter(l, &b)
		}
	}

	// start 有可能是 context 导致的错误，此时 cmd 还没有启动。
	// 所以把错误传递到下面一并处理。
	err := c.cmd.Start()
	if err == nil {
		if c.process != nil {
			*c.process = c.cmd.Process
		}
		err = c.cmd.Wait()
	}

	if err != nil {
		if c.exitOnError {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if c.ignoreErrors {
			return
		}
		if b.matched {
			return
		}
		for _, expect := range c.expectedErrors {
			if strings.Contains(err.Error(), expect) {
				return
			}
		}
		panic(fmt.Errorf("shell: unexpected error: %w\n%s", err, c.cmd.String()))
	}
}

type _Bound struct {
	options []Option
}

func Bind(options ...Option) _Bound {
	return _Bound{options: options}
}

func (b _Bound) Bind(options ...Option) _Bound {
	opts := []Option{}
	opts = append(opts, b.options...)
	opts = append(opts, options...)
	return _Bound{options: opts}
}

func (b _Bound) Run(cmdline string, options ...Option) {
	opt := append([]Option{}, b.options...)
	opt = append(opt, options...)
	Run(cmdline, opt...)
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
func Run(cmdline string, options ...Option) {
	parse(cmdline, options...).Run()
}

func parse(cmdline string, options ...Option) *_Command {
	c := &_Command{
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

	c.cmd.SysProcAttr = &syscall.SysProcAttr{}

	if !c.detach {
		c.setDeathSignal()
	}

	if c.uid > 0 || c.gid > 0 {
		if c.cmd.SysProcAttr.Credential == nil {
			c.cmd.SysProcAttr.Credential = &syscall.Credential{}
		}
		if c.uid > 0 {
			c.cmd.SysProcAttr.Credential.Uid = c.uid
		}
		if c.gid > 0 {
			c.cmd.SysProcAttr.Credential.Gid = c.gid
			c.cmd.SysProcAttr.Credential.NoSetGroups = true
		}
	}

	return c
}

func WithIf(cond bool, opt Option) Option {
	return func(c *_Command) {
		if cond {
			opt(c)
		}
	}
}

// 追加环境变量。
//
// v的类型是any，会被用fmt.Sprint转换成字符串。
func WithEnv(k string, v any) Option {
	return func(c *_Command) {
		c.env[k] = v
	}
}

// 输出进程对象。
func WithOutputProcess(process **os.Process) Option {
	return func(c *_Command) {
		c.process = process
	}
}

// `${self}` == os.Args[0]
// 是否应该总是默认添加？
func WithCmdSelf() Option {
	return func(c *_Command) {
		c.interpolations[`self`] = os.Args[0]
	}
}

// 以指定的用户运行进程。
func WithUID(uid uint32) Option {
	return func(c *_Command) {
		c.uid = uid
	}
}

// 以指定用户组运行进程。
func WithGID(gid uint32) Option {
	return func(c *_Command) {
		c.gid = gid
	}
}

func WithStdin(r io.Reader) Option {
	return func(c *_Command) {
		if c.stdin != nil {
			panic(`stdin already set`)
		}
		c.stdin = r
	}
}
func WithInteractive() Option {
	return WithStdin(os.Stdin)
}

// 设定标准输出。
//
// 即便设定为 os.Stdout，暂时也不支持伪终端特性。
func WithStdout(w io.Writer) Option {
	return func(c *_Command) {
		if c.stdout != nil {
			panic(`stdout already set`)
		}
		c.stdout = w
	}
}

// 设定标准错误输出。
//
// 即便设定为 os.Stderr，暂时也不支持伪终端特性。
func WithStderr(w io.Writer) Option {
	return func(c *_Command) {
		if c.stderr != nil {
			panic(`stderr already set`)
		}
		c.stderr = w
	}
}

func WithTTY() Option {
	return func(c *_Command) {
		WithStdout(os.Stdout)(c)
		WithStderr(os.Stderr)(c)
	}
}

// 同时设置 Stdout 和 Stderr。
func WithCombined(w io.Writer) Option {
	return func(c *_Command) {
		c.stdout = w
		c.stderr = w
	}
}

func WithDir(dir string) Option {
	return func(c *_Command) {
		c.dir = dir
	}
}

// 解析 cmdline 之后再追加到其后。
func WithArgs(args ...string) Option {
	return func(c *_Command) {
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

// 设置变量替换。
//
// 命令行解析后才会被替换，所以不存在类似“包含空格的字符串被解析成两个参数”这样的行为。
//
// pairs: [string, any, string, any, ...]
func WithValues(pairs ...any) Option {
	if len(pairs)%2 != 0 {
		panic(`invalid interpolations values`)
	}
	return func(c *_Command) {
		for i := 0; i < len(pairs)/2; i++ {
			k := pairs[i*2+0].(string)
			v := pairs[i*2+1]
			c.interpolations[k] = v
		}
	}
}
func WithContext(ctx context.Context) Option {
	return func(c *_Command) {
		c.ctx = ctx
	}
}

// 如果运行时出错，则直接报错并退出。
// 错误基于退出码非零判断。
func WithExitOnError() Option {
	return func(c *_Command) {
		c.exitOnError = true
	}
}

// 忽略包含指定字符串的错误行。
//
// 错误可以来自：标准输出、标准错误输出、命令执行返回的错误（err）。
// 仅在进程运行出错（如：退出码不为0）时才会判断此错误列表。
//
// 如果不带参数，会忽略命令执行时返回的错误（err）。
func WithIgnoreErrors(contains ...string) Option {
	return func(c *_Command) {
		c.expectedErrors = append(c.expectedErrors, contains...)
		c.ignoreErrors = len(c.expectedErrors) <= 0
	}
}

// 主进程退出时不随主进程一起退出。
func WithDetach() Option {
	return func(c *_Command) {
		c.detach = true
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

// 用于允许stdout和stderr被设置为同一个(multi包装后的)writer。
type _LockedWriter struct {
	w io.Writer
	l sync.Mutex
}

func (w *_LockedWriter) Write(p []byte) (int, error) {
	w.l.Lock()
	defer w.l.Unlock()
	return w.w.Write(p)
}

type _ErrorMatcher struct {
	errors  []string
	matched bool
	lock    sync.Mutex
	remain  []byte
}

func (e *_ErrorMatcher) Write(p []byte) (int, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	lines := strings.Split(string(p), "\n")

	test := func(s string) {
		for _, expect := range e.errors {
			if strings.Contains(s, expect) {
				e.matched = true
			}
		}
	}

	// 第一行前面可能有未处理完的数据，追加并判断
	line0 := lines[0]
	if len(e.remain) > 0 {
		line0 = string(e.remain) + line0
		e.remain = nil
	}
	test(line0)

	// ...最后一行之前的所有行。
	for i := 1; i < len(lines)-1; i++ {
		test(lines[i])
	}

	// 最后一行如果不以换行结束，可能需要缓存。
	if len(lines) > 1 {
		last := lines[len(lines)-1]
		if last == "" {
			// 最后以换行符结束，前面已经判断过了。
		} else {
			test(last)
			// 继续留着下一次追加判断。
			e.remain = []byte(last)
		}
	} else {
		e.remain = []byte(line0)
	}

	return len(p), nil
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
