package runner

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/commandgroup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestStartCommandWithoutCgroup(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSYS, syscall.EINVAL, syscall.EOPNOTSUPP, syscall.EPERM, syscall.EACCES, syscall.EBUSY, syscall.ENOENT} {
		t.Run(errno.Error(), func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "/bin/true")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, UseCgroupFD: true, CgroupFD: 123}
			calls := 0
			started, err := commandgroup.StartCommand(t.Context(), cmd, func(c *exec.Cmd) error {
				calls++
				if calls == 1 {
					return &os.PathError{Op: "fork/exec", Err: errno}
				}
				require.False(t, c.SysProcAttr.UseCgroupFD)
				assert.True(t, c.SysProcAttr.Setsid)
				return c.Start()
			})
			require.NoError(t, err)
			defer func() { assert.NoError(t, started.Wait()) }()
			am := newTestAuthManager()
			pid := started.Process.Pid
			am.registerStartedCommand(pid, "command-id", "alice", "", "/agent/alpamon-command-test")
			sid, err := unix.Getsid(pid)
			require.NoError(t, err)
			session, _ := am.sudoSessionLocked(sudoIdentity{sid: sid, sidOK: true, group: "/local"})
			require.NotNil(t, session)
			assert.Equal(t, "command-id", session.CommandID)
			assert.Empty(t, session.groupPath)
			assert.Equal(t, 2, calls)
		})
	}
}
