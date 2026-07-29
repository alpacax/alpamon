//go:build !windows

package executor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if strings.Contains(output, "ALPAMON_LEAK_CANARY") {
		t.Errorf("process environment leaked into child:\n%s", output)
	}
	if !strings.Contains(output, "HOME=") {
		t.Errorf("expected HOME to be set in child env, got:\n%s", output)
	}
	if !strings.Contains(output, "USER=") {
		t.Errorf("expected USER to be set in child env, got:\n%s", output)
	}
}

// TestExecutor_ExecEnvReachesShell verifies that caller-provided env overrides
// (e.g. the package proxy for closed-network upgrades) actually reach the
// spawned shell, while Alpamon's own process environment stays untouched.
func TestExecutor_ExecEnvReachesShell(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	env := map[string]string{
		"https_proxy": "http://proxy.internal:3128",
		"no_proxy":    "localhost,169.254.169.254",
	}

	exitCode, output, err := e.Exec(ctx, []string{"sh", "-c", `printf '%s|%s' "$https_proxy" "$no_proxy"`}, "", "", env, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if output != "http://proxy.internal:3128|localhost,169.254.169.254" {
		t.Errorf("env override did not reach the shell, got %q", output)
	}
	if got := os.Getenv("https_proxy"); got != "" {
		t.Errorf("child env override leaked into the agent process: https_proxy=%q", got)
	}
}
