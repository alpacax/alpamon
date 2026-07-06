//go:build !windows

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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

func TestExecutor_TimeoutCleansProcessTreeWhenChildKeepsPipeOpen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pidHook func(pid int)
	}{
		{
			name: "plain",
		},
		{
			name:    "pid_hook",
			pidHook: func(pid int) {},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			script := "sleep 600 & echo $! > \"$1\"; wait"

			type result struct {
				exitCode int
				output   string
				err      error
			}
			done := make(chan result, 1)
			go func() {
				exitCode, output, err := NewExecutor().Execute(context.Background(), CommandOptions{
					Args:    []string{"/bin/sh", "-c", script, "sh", pidFile},
					Timeout: 200 * time.Millisecond,
					PIDHook: tc.pidHook,
				})
				done <- result{exitCode: exitCode, output: output, err: err}
			}()

			var res result
			select {
			case res = <-done:
			case <-time.After(5 * time.Second):
				pid := readExecutorTimeoutChildPID(t, pidFile)
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("executor did not return after timeout; leaked child pid %d", pid)
			}

			if res.exitCode != 124 {
				t.Fatalf("exit code: got %d, want 124; err=%v output=%q", res.exitCode, res.err, res.output)
			}
			if res.err == nil {
				t.Fatal("expected timeout error")
			}
			if !strings.Contains(res.output, "Command timed out after") {
				t.Fatalf("expected timeout banner, got %q", res.output)
			}

			pid := readExecutorTimeoutChildPID(t, pidFile)
			t.Cleanup(func() {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			})
			if !waitForExecutorTimeoutChildExit(pid, 3*time.Second) {
				t.Fatalf("child process %d was still alive after executor timeout cleanup", pid)
			}
		})
	}
}

func readExecutorTimeoutChildPID(t *testing.T, path string) int {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if convErr != nil {
				t.Fatalf("invalid pid file %q: %v", string(data), convErr)
			}
			return pid
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid file was not written: %s: %v", path, lastErr)
	return 0
}

func waitForExecutorTimeoutChildExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if processGone(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return processGone(pid)
}

// processGone reports whether pid has stopped running. kill(pid, 0) still
// succeeds for a zombie, and the test isn't sleep's parent so it can't reap
// it directly; in a CI container with no init process to reap the orphaned
// grandchild, it stays a zombie indefinitely, so also accept that state.
func processGone(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	idx := strings.LastIndexByte(string(data), ')')
	return idx != -1 && idx+2 < len(data) && data[idx+2] == 'Z'
}
