package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lockedBuffer lets the Cancel hook's goroutine and the test share one log sink.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// cleanupLogLine is one process-tree cleanup line: decoded, and as written.
type cleanupLogLine struct {
	fields map[string]any
	raw    string
}

// captureCleanupLog points the global logger at a buffer for the test and returns a reader of the
// process-tree cleanup lines written so far.
func captureCleanupLog(t *testing.T) func() []cleanupLogLine {
	t.Helper()
	sink := &lockedBuffer{}
	orig := log.Logger
	log.Logger = zerolog.New(sink).Level(zerolog.DebugLevel)
	t.Cleanup(func() { log.Logger = orig })
	return func() []cleanupLogLine {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		var lines []cleanupLogLine
		for _, raw := range strings.Split(strings.TrimSpace(sink.buf.String()), "\n") {
			if raw == "" {
				continue
			}
			var line map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &line), "log line %q", raw)
			if line["message"] == "Cleaned up the command's process tree." {
				lines = append(lines, cleanupLogLine{fields: line, raw: raw})
			}
		}
		return lines
	}
}

func TestLogProcessTreeCleanup_LevelFollowsWhatWasKilled(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reason    string
		outcome   cleanupOutcome
		err       error
		wantLevel string
	}{
		{name: "routine exit kills nothing", reason: cleanupReasonExit, outcome: cleanupOutcome{assigned: true}, wantLevel: "debug"},
		{name: "already gone is not an error", reason: cleanupReasonExit, err: os.ErrProcessDone, wantLevel: "debug"},
		{name: "exit leaves job members", reason: cleanupReasonExit, outcome: cleanupOutcome{assigned: true, active: 2}, wantLevel: "info"},
		{name: "exit kills a leftover group member", reason: cleanupReasonExit, outcome: cleanupOutcome{rootKilled: true}, wantLevel: "info"},
		{name: "timeout", reason: cleanupReasonTimeout, wantLevel: "info"},
		{name: "shutdown", reason: cleanupReasonShutdown, wantLevel: "info"},
		{name: "wait delay", reason: cleanupReasonWaitDelay, wantLevel: "info"},
		{name: "a failed cleanup that killed nothing is not hidden", reason: cleanupReasonExit, outcome: cleanupOutcome{assigned: true}, err: errors.New("terminate job: access denied"), wantLevel: "warn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := captureCleanupLog(t)
			logProcessTreeCleanup("cmd-1", &exec.Cmd{}, tc.reason, tc.outcome, tc.err)

			lines := read()
			require.Len(t, lines, 1)
			line := lines[0].fields
			assert.Equal(t, tc.wantLevel, line["level"])
			assert.Equal(t, "cmd-1", line["command_id"])
			assert.Equal(t, tc.reason, line["reason"])
			assert.Equal(t, tc.outcome.assigned, line["assigned"])
			assert.EqualValues(t, tc.outcome.active, line["active"])
			assert.Equal(t, tc.outcome.rootKilled, line["root_killed"])
			if tc.err == nil || errors.Is(tc.err, os.ErrProcessDone) {
				assert.NotContains(t, line, "error", "os.ErrProcessDone must not be logged as an error")
			} else {
				assert.Equal(t, tc.err.Error(), line["error"])
			}
		})
	}

	t.Run("a real error is kept", func(t *testing.T) {
		read := captureCleanupLog(t)
		logProcessTreeCleanup("", &exec.Cmd{}, cleanupReasonExit, cleanupOutcome{}, errors.New("boom"))
		lines := read()
		require.Len(t, lines, 1)
		assert.Equal(t, "boom", lines[0].fields["error"])
	})
}

// A timed-out command gets one Info line naming its command ID and the reason, and no cleanup line
// carries an argument of the command.
func TestExecutor_TimeoutLogsOneCleanupLineWithCommandID(t *testing.T) {
	const sentinel = "cleanup-log-sentinel-3f9a1c"
	// The sentinel is $0 of the shell, or a cmd.exe remark: on the command line, inert when it runs.
	args := []string{"/bin/sh", "-c", "sleep 10", sentinel}
	if runtime.GOOS == "windows" {
		args = []string{"cmd", "/c", "ping", "-n", "10", "127.0.0.1", "&", "rem", sentinel}
	}
	read := captureCleanupLog(t)

	exitCode, _, err := NewExecutor().Execute(context.Background(), CommandOptions{
		Args:      args,
		Timeout:   300 * time.Millisecond,
		CommandID: "cmd-timeout",
	})
	require.Error(t, err)
	require.Equal(t, 124, exitCode)

	var timeouts []map[string]any
	for _, line := range read() {
		assert.Equal(t, "cmd-timeout", line.fields["command_id"])
		assert.NotContains(t, line.raw, sentinel, "a command argument reached the cleanup log")
		if line.fields["reason"] == cleanupReasonTimeout {
			timeouts = append(timeouts, line.fields)
		}
	}
	require.Len(t, timeouts, 1, "want exactly one timeout cleanup line")
	assert.Equal(t, "info", timeouts[0]["level"])
	assert.Equal(t, true, timeouts[0]["root_killed"])
}
