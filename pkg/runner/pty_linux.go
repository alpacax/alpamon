package runner

import (
	"fmt"
	"math"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

func (pc *PtyClient) setPtyCmdSysProcAttrAndEnv(uid, gid int, groupIds []string, env map[string]string) {
	if uid < 0 || uid > math.MaxUint32 {
		return
	}
	if gid < 0 || gid > math.MaxUint32 {
		return
	}
	pc.cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: utils.ConvertGroupIds(groupIds),
		},
	}
	pc.cmd.Dir = env["HOME"]

	for key, value := range env {
		pc.cmd.Env = append(pc.cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
}
