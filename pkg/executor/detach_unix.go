//go:build !windows

package executor

import (
	"os/exec"
	"syscall"
)

// StartDetached starts name as root in a new session and returns without waiting. It skips the
// process-tree cleanup every other method applies, which kills whatever a command leaves running when
// it exits, so it is only for work that must outlive the agent, such as a deferred self-uninstall.
func (e *Executor) StartDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	for key, value := range e.buildEnv("root", nil) {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.Dir = "/"
	// Its own session and process group, so no command cleanup and no signal to the agent's group reaches it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reaps it if it ends while the agent still runs; nothing here ever signals it.
	go func() { _ = cmd.Wait() }()
	return nil
}
