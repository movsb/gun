package targets

import "os/exec"

func hasCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func hasGroupAdd() bool {
	return hasCommand(`groupadd`) || hasCommand(`addgroup`)
}
