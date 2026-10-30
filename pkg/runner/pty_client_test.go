//go:build !windows

package runner

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/shirou/gopsutil/v4/process"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPtyClientChannelsUseChannelCapacity(t *testing.T) {
	pc := NewPtyClient(protocol.CommandData{}, nil, nil)

	assert.Equal(t, channelCapacity, cap(pc.ptyToWs))
	assert.Equal(t, channelCapacity, cap(pc.wsToPty))
}

func BenchmarkNewPtyClient(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewPtyClient(protocol.CommandData{}, nil, nil)
	}
}

func TestPtyClientClose_RemovesPIDMappingFromInjectedAuthManager(t *testing.T) {
	prev := SwapAuthManager(nil) // The package global must play no part.
	t.Cleanup(func() { SwapAuthManager(prev) })
	am := newTestAuthManager()
	cmd := exec.Command("sleep", "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := cmd.Process.Pid
	am.AddPIDSessionMapping(pid, &SessionInfo{SessionID: "s1"})
	pc := &PtyClient{sessionID: "s1", cmd: cmd, manager: NewTerminalManager(am)}

	pc.close()

	_, ok := am.LookupPID(pid)
	assert.False(t, ok, "PID mapping survived close")
}

func TestPtyCloseKillsBackgroundChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", `trap '' HUP; sleep 600 & echo $! > "$1"; wait`, "sh", pidFile)
	ptmx, err := pty.Start(cmd)
	require.NoError(t, err)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = ptmx.Close()
			_ = cmd.Wait()
		}
	})
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	pc := &PtyClient{sessionID: "background", cmd: cmd, ptmx: ptmx, manager: NewTerminalManager(nil)}
	pc.close()
	closed = true
	assert.Eventually(t, func() bool {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return true
		}
		s, err := p.Status()
		return err != nil || slices.Contains(s, process.Zombie)
	}, time.Second, 10*time.Millisecond, "background child survived terminal close")
}

func TestPtyCloseInteractiveBackgroundChild(t *testing.T) {
	canary := exec.Command("sleep", "600")
	canary.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	require.NoError(t, canary.Start())
	t.Cleanup(func() { _ = canary.Process.Kill(); _ = canary.Wait() })
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-i")
	ptmx, err := pty.Start(cmd)
	require.NoError(t, err)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = ptmx.Close()
			_ = cmd.Wait()
		}
	})
	_, err = fmt.Fprintf(ptmx, "sleep 600 & echo $! > %q\n", pidFile)
	require.NoError(t, err)
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	group, err := syscall.Getpgid(pid)
	require.NoError(t, err)
	require.NotEqual(t, cmd.Process.Pid, group, "interactive job control must put the child in another group")
	pc := &PtyClient{sessionID: "interactive", cmd: cmd, ptmx: ptmx, manager: NewTerminalManager(nil)}
	pc.close()
	closed = true
	assert.Eventually(t, func() bool {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return true
		}
		s, err := p.Status()
		return err != nil || slices.Contains(s, process.Zombie)
	}, time.Second, 10*time.Millisecond, "interactive background child survived terminal close")
	assert.NoError(t, canary.Process.Signal(syscall.Signal(0)), "another session must stay alive")
}
