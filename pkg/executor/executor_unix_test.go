//go:build !windows

package executor

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecutor_DoesNotInheritProcessEnv verifies that on Unix a command run
// without an explicit environment does not inherit Alpamon's own process
// environment, and that identity variables are populated instead. Windows
// intentionally inherits the process environment (see baseenv_windows.go).
func TestExecutor_DoesNotInheritProcessEnv(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	// A variable present in Alpamon's process environment must not leak into
	// the child when no explicit env is provided.
	t.Setenv("ALPAMON_LEAK_CANARY", "leaked")

	exitCode, output, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"env"},
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	assert.NotContains(t, output, "ALPAMON_LEAK_CANARY", "process environment leaked into child")
	assert.Contains(t, output, "HOME=", "expected HOME to be set in child env")
	assert.Contains(t, output, "USER=", "expected USER to be set in child env")
}

// TestExecutor_ExecEnvReachesShell verifies that caller-provided env overrides
// (e.g. the package proxy for closed-network upgrades) actually reach the
// spawned shell, while Alpamon's own process environment stays untouched.
func TestExecutor_ExecEnvReachesShell(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	// CI or developer shells may already export https_proxy; assert the value
	// is unchanged after Exec rather than assuming it starts empty.
	preexisting := os.Getenv("https_proxy")

	env := map[string]string{
		"https_proxy": "http://proxy.internal:3128",
		"no_proxy":    "localhost,169.254.169.254",
	}

	exitCode, output, err := e.Exec(ctx, []string{"sh", "-c", `printf '%s|%s' "$https_proxy" "$no_proxy"`}, "", "", env, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	assert.Equal(t, "http://proxy.internal:3128|localhost,169.254.169.254", output, "env override did not reach the shell")
	assert.Equal(t, preexisting, os.Getenv("https_proxy"), "child env override leaked into the agent process")
}
