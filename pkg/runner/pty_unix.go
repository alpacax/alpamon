//go:build !windows

package runner

import (
	"fmt"
	"math"
	"os"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

func (pc *PtyClient) setPtyCmdSysProcAttrAndEnv(uid, gid int, groupIds []string, env map[string]string) error {
	// Only set credentials when running as root; non-root cannot demote.
	currentUID := os.Getuid()
	if currentUID == 0 {
		u32uid, u32gid, err := safeUint32Credentials(uid, gid)
		if err != nil {
			return err
		}
		pc.cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:    u32uid,
				Gid:    u32gid,
				Groups: utils.ConvertGroupIds(groupIds),
			},
		}
	} else if uid != currentUID {
		log.Warn().Int("requestedUID", uid).Int("processUID", currentUID).
			Msg("PTY credential demotion skipped: alpamon is not running as root. Session will run as the alpamon process user.")
	}

	pc.cmd.Dir = env["HOME"]

	for key, value := range env {
		pc.cmd.Env = append(pc.cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	return nil
}

func safeUint32Credentials(uid, gid int) (uint32, uint32, error) {
	if uid < 0 || uid > math.MaxUint32 {
		return 0, 0, fmt.Errorf("UID %d is out of valid range", uid)
	}
	if gid < 0 || gid > math.MaxUint32 {
		return 0, 0, fmt.Errorf("GID %d is out of valid range", gid)
	}
	return uint32(uid), uint32(gid), nil // #nosec G115
}
