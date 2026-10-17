//go:build !windows

package executor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// StartDetached must put the command in a session of its own, so the group kill that ends every other
// command cannot reach it.
func TestExecutor_StartDetachedRunsInItsOwnSession(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ids")
	// Writes its PID, then lingers so its session can be read while it still runs.
	script := `echo $$ > "$1.tmp" && mv "$1.tmp" "$1"; sleep 2`
	require.NoError(t, NewExecutor().StartDetached("/bin/sh", "-c", script, "sh", out))

	var pid int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(out)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the detached command did not run")

	sid, err := unix.Getsid(pid)
	require.NoError(t, err, "getsid")
	assert.Equal(t, pid, sid, "the detached command does not lead its own session")
	ownSID, err := unix.Getsid(0)
	require.NoError(t, err, "getsid self")
	assert.NotEqual(t, ownSID, sid, "the detached command shares the agent's session")
}
