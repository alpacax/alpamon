//go:build !windows

package commandgroup

import (
	"os"
	"os/exec"
	"strconv"
)

func startUID(cmd *exec.Cmd) string {
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		return strconv.FormatUint(uint64(cmd.SysProcAttr.Credential.Uid), 10)
	}
	return strconv.Itoa(os.Getuid())
}
