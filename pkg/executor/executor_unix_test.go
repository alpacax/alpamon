//go:build !windows

package executor

import (
	"context"
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
