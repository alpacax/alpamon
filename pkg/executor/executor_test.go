package executor

import (
	"context"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_TimeoutReturns124(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	exitCode, output, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"sleep", "10"},
		Timeout: 500 * time.Millisecond,
	})

	assert.Equal(t, 124, exitCode, "expected exit code 124")
	assert.Contains(t, output, "Command timed out after", "expected timeout message in output")
	assert.Error(t, err, "expected non-nil error on timeout")
}

func TestExecute_GivenParentCtxCancelledMidRun_ThenExitCodeIsOneNotNegativeOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execs the POSIX sleep binary")
	}
	e := NewExecutor()
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	exitCode, _, err := e.Execute(ctx, CommandOptions{
		Args: []string{"sleep", "5"},
	})

	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
}

// A fast, normally-exiting command must still stream its output through the callback.
func TestExecutor_NoTimeoutOnFastCommand(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	var captured string
	exitCode, _, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"echo", "hello"},
		Timeout: 5 * time.Second,
		ChunkCallback: func(ctx context.Context, content string) {
			captured += content
		},
	})

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, captured, "hello")
}

// Regression: ChunkCallback's ctx must be Execute's own deadline-bearing ctx (the timeout
// child it creates), not the caller's ctx, so a queued chunk gets a matching expiry.
func TestExecute_GivenTimeoutOption_WhenChunkEmitted_ThenCallbackCtxCarriesThatDeadline(t *testing.T) {
	e := NewExecutor()
	outerCtx := context.Background()

	var gotCtx context.Context
	_, _, err := e.Execute(outerCtx, CommandOptions{
		Args:    []string{"echo", "hi"},
		Timeout: 5 * time.Second,
		ChunkCallback: func(ctx context.Context, content string) {
			gotCtx = ctx
		},
	})
	require.NoError(t, err)

	require.NotNil(t, gotCtx, "ChunkCallback should have been invoked")
	_, outerHasDeadline := outerCtx.Deadline()
	require.False(t, outerHasDeadline, "test setup: outer ctx must not itself carry a deadline")
	_, hasDeadline := gotCtx.Deadline()
	assert.True(t, hasDeadline, "callback ctx should carry Execute's own timeout, not the deadline-less outer ctx")
}

func TestExecutor_ExecWithStreamingHook_StreamsChunks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}

	e := NewExecutor()
	ctx := context.Background()

	var mu sync.Mutex
	var chunks []string
	callback := func(_ context.Context, content string) {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, content)
	}

	exitCode, output, err := e.ExecWithStreamingHook(
		ctx,
		[]string{"/bin/sh", "-c", "printf 'line1\\nline2\\nline3\\n'"},
		"", "", nil, 5*time.Second, nil, callback,
	)
	require.NoError(t, err, "ExecWithStreamingHook")
	assert.Equal(t, 0, exitCode, "exit code")

	mu.Lock()
	defer mu.Unlock()

	require.NotEmpty(t, chunks, "expected at least one chunk")
	assembled := strings.Join(chunks, "")
	assert.Contains(t, assembled, "line1", "unexpected chunks")
	assert.Contains(t, assembled, "line3", "unexpected chunks")
	// The streaming path returns a capped audit copy so fin carries output even if chunks drop.
	assert.Equal(t, assembled, output, "captured output should match streamed chunks")
}

func TestExecutor_StartFailureSurfacesErrorInResult(t *testing.T) {
	e := NewExecutor()
	missing := "/no/such/binary/should/exist/here-" + t.Name()

	exitCode, result, err := e.Execute(context.Background(), CommandOptions{
		Args:    []string{missing},
		Timeout: 5 * time.Second,
	})
	require.Error(t, err, "expected error for missing binary")
	assert.NotEqual(t, 0, exitCode, "expected non-zero exit")
	assert.True(t, strings.Contains(result, missing) || strings.Contains(result, "no such file"), "result should carry start-failure diagnostic, got %q", result)
}

func TestExecutor_StreamingTimeoutBannerHasNoLeadingNewlines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}
	e := NewExecutor()
	exitCode, result, err := e.ExecWithStreamingHook(
		context.Background(),
		[]string{"/bin/sh", "-c", "sleep 5"},
		"", "", nil, 500*time.Millisecond,
		nil, func(_ context.Context, content string) {},
	)
	require.Error(t, err, "expected timeout error")
	assert.Equal(t, 124, exitCode)
	assert.False(t, strings.HasPrefix(result, "\n"), "streaming timeout banner should not have leading newline: %q", result)
	assert.True(t, strings.HasPrefix(result, "Command timed out after"), "unexpected banner: %q", result)
}

func TestExecutor_PlainExecuteWithoutCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}

	e := NewExecutor()
	exitCode, output, err := e.Execute(context.Background(), CommandOptions{
		Args:    []string{"/bin/sh", "-c", "printf 'hello\\n'"},
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err, "Execute")
	assert.Equal(t, 0, exitCode, "exit code")
	assert.Contains(t, output, "hello")
}

// TestExecutor_BuildEnvSetsUserIdentity verifies the environment is populated
// with the resolved user's identity and the deterministic defaults.
func TestExecutor_BuildEnvSetsUserIdentity(t *testing.T) {
	e := NewExecutor()

	usr, err := user.Current()
	require.NoError(t, err, "failed to get current user")

	// Empty username resolves to the current user (Alpamon is not root in tests).
	env := e.buildEnv("", nil)

	assert.Equal(t, usr.HomeDir, env["HOME"], "HOME")
	assert.Equal(t, usr.Username, env["USER"], "USER")
	assert.Equal(t, usr.Username, env["LOGNAME"], "LOGNAME")
	for _, key := range []string{"PATH", "SHELL", "TERM", "LANG"} {
		assert.NotEmpty(t, env[key], "expected default env %q to be set", key)
	}
}

// TestExecutor_BuildEnvOverridePrecedence verifies caller-provided env values
// take precedence over both the defaults and the resolved user identity.
func TestExecutor_BuildEnvOverridePrecedence(t *testing.T) {
	e := NewExecutor()

	env := e.buildEnv("", map[string]string{
		"HOME": "/custom/home",
		"FOO":  "bar",
	})

	assert.Equal(t, "/custom/home", env["HOME"], "expected override HOME")
	assert.Equal(t, "bar", env["FOO"], "expected FOO")
}

// TestExecutor_ExpandArgsUsesBuiltEnv locks in the behavior that argument
// variable references are expanded from the synthesized environment even when
// the caller passes no env (previously such args were left untouched).
func TestExecutor_ExpandArgsUsesBuiltEnv(t *testing.T) {
	e := NewExecutor()

	env := e.buildEnv("", nil)
	args := e.expandArgs([]string{"echo", "$HOME", "${USER}"}, env)

	require.Len(t, args, 3)
	assert.Equal(t, env["HOME"], args[1], "expected $HOME expanded")
	assert.Equal(t, env["USER"], args[2], "expected ${USER} expanded")
}
