package executor

import (
	"context"
	"runtime"
	"strings"
	"sync"
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

// TestExecutor_ExecWithStreamingHook_StreamsChunks runs a real command and
// verifies that ChunkCallback is invoked, the assembled chunk content matches
// the returned combined output, and the chunks arrive in produced order.
func TestExecutor_ExecWithStreamingHook_StreamsChunks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}

	e := NewExecutor()
	ctx := context.Background()

	var mu sync.Mutex
	var chunks []string
	callback := func(content string) {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, content)
	}

	exitCode, output, err := e.ExecWithStreamingHook(
		ctx,
		[]string{"/bin/sh", "-c", "printf 'line1\\nline2\\nline3\\n'"},
		"", "", nil, 5*time.Second, nil, callback,
	)
	if err != nil {
		t.Fatalf("ExecWithStreamingHook: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	if got, want := strings.Join(chunks, ""), output; got != want {
		t.Errorf("assembled chunks do not match output:\nchunks: %q\noutput: %q", got, want)
	}
	if !strings.Contains(output, "line1") || !strings.Contains(output, "line3") {
		t.Errorf("unexpected output: %q", output)
	}
}

// TestExecutor_PlainExecuteWithoutCallback ensures the non-streaming code path
// is unchanged when ChunkCallback is nil — output is captured via the legacy
// CombinedOutput route.
func TestExecutor_PlainExecuteWithoutCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}

	e := NewExecutor()
	exitCode, output, err := e.Execute(context.Background(), CommandOptions{
		Args:    []string{"/bin/sh", "-c", "printf 'hello\\n'"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
	if !strings.Contains(output, "hello") {
		t.Errorf("output: got %q", output)
	}
}
