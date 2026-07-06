//go:build windows

package executor

import (
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCommandCleanup_CancelTerminatesViaJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	defer cleanup.close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	if err := cleanup.afterStart(cmd); err != nil {
		t.Fatalf("afterStart: %v", err)
	}
	if !cleanup.assigned {
		t.Fatal("expected the process to be assigned to the job object")
	}

	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForCmd(t, cmd)
	if isWindowsPidAlive(pid) {
		t.Fatalf("process %d still running after cancel", pid)
	}
}

func TestCommandCleanup_CancelFallsBackToPIDTreeWithoutJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	defer cleanup.close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	// Skip afterStart so cancel has no job/handle and must fall back to the PID tree walk alone.
	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForCmd(t, cmd)
	if isWindowsPidAlive(pid) {
		t.Fatalf("process %d still running after cancel", pid)
	}
}

func waitForCmd(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmd.Wait did not return after cancel")
	}
}

func isWindowsPidAlive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	event, err := windows.WaitForSingleObject(h, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}
