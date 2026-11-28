//go:build !windows

package executor

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestExecutor_ProcessObserverTracksCommandsWithoutPIDHook(t *testing.T) {
	for _, method := range []string{"Run", "RunAsUser", "RunWithInput", "RunWithTimeout", "Exec"} {
		t.Run(method, func(t *testing.T) {
			var observedPID int
			ctx := common.WithProcessObserver(context.Background(), func(_ string, pid int) {
				observedPID = pid
			})
			e := NewExecutor()
			args := []string{"/bin/sh", "-c", "printf governed"}
			var code int
			var output string
			var err error
			switch method {
			case "Run":
				code, output, err = e.Run(ctx, args[0], args[1:]...)
			case "RunAsUser":
				code, output, err = e.RunAsUser(ctx, "", args[0], args[1:]...)
			case "RunWithInput":
				code, output, err = e.RunWithInput(ctx, "", args[0], args[1:]...)
			case "RunWithTimeout":
				code, output, err = e.RunWithTimeout(ctx, time.Second, args[0], args[1:]...)
			case "Exec":
				code, output, err = e.Exec(ctx, args, "", "", nil, time.Second)
			}
			require.NoError(t, err)
			assert.Zero(t, code)
			assert.Equal(t, "governed", output)
			assert.Greater(t, observedPID, 1, "every common executor entry point must report the process")
		})
	}
}

func TestExecutor_ProcessObserverReceivesSessionLeader(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var observedPID, observedSID int
	var sessionErr, inputErr error
	ctx := common.WithProcessObserver(context.Background(), func(_ string, pid int) {
		observedPID = pid
		observedSID, sessionErr = unix.Getsid(pid)
		_, inputErr = writer.Write([]byte("ready\n"))
	})
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "read value; printf observed")
	cmd.Stdin = reader
	output, err := NewExecutor().runCommand(ctx, cmd, "", nil, nil)
	require.NoError(t, err)
	require.NoError(t, sessionErr)
	require.NoError(t, inputErr)
	assert.Equal(t, "observed", string(output))
	assert.Greater(t, observedPID, 1)
	assert.Equal(t, observedPID, observedSID, "governed commands must lead the session the registry owns")
}

func TestExecutor_ProcessObserverPreservesPIDHook(t *testing.T) {
	for _, panicHook := range []bool{false, true} {
		t.Run(map[bool]string{false: "PAM hook", true: "panicking PAM hook"}[panicHook], func(t *testing.T) {
			var observedID string
			var observedPID, pamPID int
			ctx := common.WithProcessObserver(context.Background(), func(id string, pid int) {
				observedID, observedPID = id, pid
			})
			code, _, err := NewExecutor().Execute(ctx, CommandOptions{
				Args:      []string{"/bin/sh", "-c", "printf governed"},
				CommandID: "command-1",
				PIDHook: func(pid int) {
					pamPID = pid
					if panicHook {
						panic("PAM hook failed")
					}
				},
			})
			require.NoError(t, err)
			assert.Zero(t, code)
			assert.Equal(t, "command-1", observedID)
			assert.Greater(t, pamPID, 1)
			assert.Equal(t, pamPID, observedPID)
		})
	}
}
