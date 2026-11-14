//go:build unix

package provision

import (
	"os/exec"
	"syscall"
)

// ownGroup starts cmd in a new process group, so everything it starts can
// be killed together.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// killGroup kills cmd's process group (the shell and every child still
// alive). Harmless when it is already gone.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
