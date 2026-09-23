package runner_test

import (
	"context"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/executor"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/shell"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A shell command's chunk stream used to outlive its own deadline because the
// callback closed over a long-lived ctx; this drives the real pipeline end to end.
func TestE2E_ShellCommandTimeout_ChunkStreamCarriesHandlerDeadlineAndDeliversFinalOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell loop; Windows routes allow_sh through PowerShell")
	}

	cleanup, contents := runner.StartFakeAlpacon(t)
	defer cleanup()

	cr := runner.NewCommandRunner(nil, nil, protocol.Command{ID: "e2e-chunk-timeout"}, protocol.CommandData{}, nil)
	realCallback := runner.NewChunkCallback(cr)
	require.NotNil(t, realCallback, "a non-empty command ID should yield a callback")

	lineRE := regexp.MustCompile(`line-(\d+)`)
	var (
		deadlines   []time.Time
		maxSentLine int
		callbackMu  sync.Mutex
	)
	wrapped := func(ctx context.Context, content string) {
		callbackMu.Lock()
		if dl, ok := ctx.Deadline(); ok {
			deadlines = append(deadlines, dl)
		}
		if m := lineRE.FindStringSubmatch(content); m != nil {
			if n, convErr := strconv.Atoi(m[1]); convErr == nil && n > maxSentLine {
				maxSentLine = n
			}
		}
		callbackMu.Unlock()
		realCallback(ctx, content)
	}

	handler := shell.NewShellHandler(executor.NewExecutor())

	const timeout = 300 * time.Millisecond
	start := time.Now()
	args := &common.CommandArgs{
		Command:       `i=0; while true; do i=$((i+1)); echo "line-$i"; sleep 0.01; done`,
		AllowSh:       true,
		Timeout:       timeout,
		ChunkCallback: wrapped,
	}
	exitCode, result, err := handler.Execute(context.Background(), common.ShellCmd.String(), args)
	require.NoError(t, err)

	assert.Equal(t, common.TimeoutExitCode, exitCode, "command should be killed with the GNU timeout exit code")
	assert.Contains(t, result, "timed out", "result should carry the timeout banner")

	// The ctx reaching the chunk callback carried the handler's own deadline,
	// not a longer-lived one—the end-to-end proof that fails on the old code.
	callbackMu.Lock()
	gotDeadlines := append([]time.Time(nil), deadlines...)
	callbackMu.Unlock()
	require.NotEmpty(t, gotDeadlines, "chunk callback should have fired at least once")
	expectedDeadline := start.Add(timeout)
	for _, dl := range gotDeadlines {
		assert.WithinDuration(t, expectedDeadline, dl, 100*time.Millisecond,
			"every chunk's ctx deadline should match the handler's own timeout")
	}

	callbackMu.Lock()
	gotMaxSentLine := maxSentLine
	callbackMu.Unlock()

	// result is the ground truth: the max line delivered over HTTP must be within a
	// small allowance of the max line the command produced, or the final flush dropped.
	require.Positive(t, gotMaxSentLine, "test setup: the command should have produced at least one line")

	// Allowance of 2: the last line or two of output can still be in flight
	// at kill time and never reach a callback.
	const allowance = 2
	var maxLine int
	require.Eventually(t, func() bool {
		maxLine = 0
		for _, c := range contents() {
			if m := lineRE.FindStringSubmatch(c); m != nil {
				if n, convErr := strconv.Atoi(m[1]); convErr == nil && n > maxLine {
					maxLine = n
				}
			}
		}
		return maxLine >= gotMaxSentLine-allowance
	}, 2*time.Second, 10*time.Millisecond,
		"delivered output should include lines produced close to the kill, proving the final flush wasn't lost")
}
