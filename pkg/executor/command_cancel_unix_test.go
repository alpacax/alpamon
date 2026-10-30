//go:build !windows

package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteCancelProcessGroup(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		name := "honors_TERM"
		if ignore {
			name = "ignores_TERM"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ready := filepath.Join(dir, "ready")
			term := filepath.Join(dir, "term")
			script := `trap 'echo term > "$2"; exit 0' TERM; echo $$ > "$1"; while :; do sleep 1; done`
			if ignore {
				script = `trap '' TERM; echo $$ > "$1"; while :; do sleep 1; done`
			}
			ctx, state := commandcancel.NewContext(context.Background())
			defer state.Cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "sh", ready, term)
			cleanup, err := configureProcessTreeCleanup(cmd, false)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				_, err := runTrackedProcessCommand(ctx, cmd, cleanup, nil, nil, "test", state, 100*time.Millisecond)
				done <- err
			}()
			pid := readCancelPID(t, ready)
			start := time.Now()
			state.Cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("cancel did not finish")
			}
			assert.True(t, waitForProcessGone(pid, time.Second), "root survived cancellation")
			if ignore {
				assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
				_, err := os.Stat(term)
				assert.ErrorIs(t, err, os.ErrNotExist)
			} else {
				assert.FileExists(t, term, "SIGTERM must run the trap before SIGKILL")
			}
			cancelled, survivors := state.Finish()
			assert.True(t, cancelled)
			assert.Empty(t, survivors)
		})
	}
}

func TestRemoteCancelBackgroundChildAfterLeaderExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child")
	ctx, state := commandcancel.NewContext(context.Background())
	defer state.Cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `trap '' TERM; sleep 10 & echo $! > "$1"; exit 0`, "sh", pidFile)
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err)
	done := make(chan error, 1)
	started := make(chan int, 1)
	go func() {
		_, err := runTrackedProcessCommand(ctx, cmd, cleanup, nil, func(pid int) { started <- pid }, "test", state, 50*time.Millisecond)
		done <- err
	}()
	child := readCancelPID(t, pidFile)
	require.True(t, waitForLeaderStopped(<-started, time.Second))
	state.Cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not finish")
	}
	assert.True(t, waitForProcessGone(child, time.Second), "background child survived cancellation")
	_, survivors := state.Finish()
	assert.Empty(t, survivors)
}

func TestTrackedCommandWithoutCancelMatchesLegacy(t *testing.T) {
	for _, script := range []string{`printf exact; exit 0`, `printf exact; exit 7`, `sleep 600 & printf exact; exit 0`, `sleep 600 & printf exact; exit 7`, `sleep 600 <&0 & printf exact; exit 0`} {
		t.Run(script, func(t *testing.T) {
			run := func(tracked bool) ([]byte, error) {
				ctx := context.Background()
				if tracked {
					var state *commandcancel.State
					ctx, state = commandcancel.NewContext(ctx)
					defer state.Finish()
				}
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
				cmd.Stdin = strings.NewReader(strings.Repeat("x", 1<<20))
				return NewExecutor().runCommand(ctx, cmd, "", nil, nil)
			}
			start := time.Now()
			oldOutput, oldErr := run(false)
			oldElapsed := time.Since(start)
			start = time.Now()
			output, err := run(true)
			assert.Less(t, time.Since(start), oldElapsed+time.Second, "tracked command must share the original pipe-drain deadline")
			assert.Equal(t, string(oldOutput), string(output))
			if oldErr == nil {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, oldErr.Error(), err.Error())
			}
		})
	}
}

func readCancelPID(t *testing.T, path string) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	return pid
}
