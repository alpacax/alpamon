package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecutor_TimeoutReturns124(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	exitCode, output, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"sleep", "10"},
		Timeout: 500 * time.Millisecond,
	})

	if exitCode != 124 {
		t.Errorf("expected exit code 124, got %d", exitCode)
	}
	if !strings.Contains(output, "Command timed out after") {
		t.Errorf("expected timeout message in output, got %q", output)
	}
	if err == nil {
		t.Error("expected non-nil error on timeout")
	}
}

func TestExecutor_NoTimeoutOnFastCommand(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	exitCode, _, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"echo", "hello"},
		Timeout: 5 * time.Second,
	})

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
