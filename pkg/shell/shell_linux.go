//go:build linux

package shell

import "syscall"

// 父进程退出时强制退出。
// 不一定会一定生效，还需要做其它兜底措施，比如强杀进程。
func (c *_Command) setDeathSignal() {
	c.cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

// 创建新的会话，脱离当前终端的前台进程组。
func (c *_Command) setNewSession() {
	c.cmd.SysProcAttr.Setsid = true
}
