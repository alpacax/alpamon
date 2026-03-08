package runner

import "fmt"

// setPtyCmdSysProcAttrAndEnv does not set SysProcAttr on macOS because macOS does not support it.
func (pc *PtyClient) setPtyCmdSysProcAttrAndEnv(uid, gid int, groupIds []string, env map[string]string) error {
	pc.cmd.Dir = env["HOME"]

	for key, value := range env {
		pc.cmd.Env = append(pc.cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	return nil
}
