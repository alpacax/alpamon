//go:build !windows

package runner

import (
	"fmt"
	"math"
	"os"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

func (pc *PtyClient) setPtyCmdSysProcAttrAndEnv(uid, gid int, groupIds []string, env map[string]string) error {
	// Only set credentials when running as root; non-root cannot demote.
	if os.Getuid() == 0 {
		if uid < 0 || uint64(uid) > uint64(math.MaxUint32) {
			return fmt.Errorf("UID %d is out of valid range", uid)
		}
		if gid < 0 || uint64(gid) > uint64(math.MaxUint32) {
			return fmt.Errorf("GID %d is out of valid range", gid)
		}
		pc.cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:    uint32(uid),
				Gid:    uint32(gid),
				Groups: utils.ConvertGroupIds(groupIds),
			},
		}
	}

	pc.cmd.Dir = env["HOME"]

	for key, value := range env {
		pc.cmd.Env = append(pc.cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	return nil
}
