//go:build !windows

package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v4/process"
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
	pid := cmd.Process.Pid
	am.AddPIDSessionMapping(pid, &SessionInfo{SessionID: "s1"})
	pc := &PtyClient{sessionID: "s1", cmd: cmd, manager: NewTerminalManager(am)}

	pc.close()

	_, ok := am.LookupPID(pid)
	assert.False(t, ok, "PID mapping survived close")
}

func TestPtyCloseKillsBackgroundChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-i")
	ptmx, err := pty.Start(cmd)
	require.NoError(t, err)
	_, err = fmt.Fprintf(ptmx, "sleep 3 & echo $! > %q\n", pidFile)
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
	require.Eventually(t, func() bool {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return false
		}
		name, err := p.Name()
		return err == nil && name == "sleep"
	}, time.Second, 50*time.Millisecond)
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

func TestPtyOrdinaryClosePreservesNohupChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-i")
	ptmx, err := pty.Start(cmd)
	require.NoError(t, err)
	// The child's timeout bounds its lifetime even on a failed test.
	_, err = fmt.Fprintf(ptmx, "nohup sleep 3 >/dev/null 2>&1 & echo $! > %q\n", pidFile)
	require.NoError(t, err)
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 3*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return false
		}
		name, err := p.Name()
		return err == nil && name == "sleep"
	}, time.Second, 50*time.Millisecond)
	pc := &PtyClient{sessionID: "nohup", cmd: cmd, ptmx: ptmx, manager: NewTerminalManager(nil)}
	pc.close()
	p, err := process.NewProcess(int32(pid))
	require.NoError(t, err, "nohup child must survive a hangup")
	statuses, err := p.Status()
	require.NoError(t, err)
	assert.NotContains(t, statuses, process.Zombie)
}

func TestPtyOpenCommandHandleLifetime(t *testing.T) {
	for _, cancelTerminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel_%v", cancelTerminal), func(t *testing.T) {
			wc := &WebsocketClient{}
			registry := &wc.cancellations
			ctx, open := registry.register(context.Background(), "openpty-id")
			ctx = context.WithValue(ctx, cancellationRegistryKey{}, registry)
			cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-i")
			ptmx, err := pty.Start(cmd)
			require.NoError(t, err)
			pc := &PtyClient{sessionID: "session", cmd: cmd, ptmx: ptmx, manager: NewTerminalManager(nil)}
			pc.TrackCommand(ctx, "openpty-id")
			t.Cleanup(pc.close)
			registry.finish("openpty-id", open)
			require.Len(t, registry.active["openpty-id"], 1, "terminal must outlive the openpty command")
			pidFile := filepath.Join(t.TempDir(), "children")
			go func() { _, _ = io.Copy(io.Discard, ptmx) }()
			duration := 3
			if cancelTerminal {
				duration = 30
				_, err = io.WriteString(ptmx, "trap '' TERM\n")
				require.NoError(t, err)
			}
			_, err = fmt.Fprintf(ptmx, "out=%q\nsleep %d & plain=$!\nnohup sleep %d >/dev/null 2>&1 & echo $plain $! > \"$out\"\n", pidFile, duration, duration)
			require.NoError(t, err)
			var pids []int
			require.Eventually(t, func() bool {
				b, err := os.ReadFile(pidFile)
				if err != nil {
					return false
				}
				fields := strings.Fields(string(b))
				if len(fields) != 2 {
					return false
				}
				pids = nil
				for _, field := range fields {
					pid, err := strconv.Atoi(field)
					if err != nil {
						return false
					}
					pids = append(pids, pid)
				}
				for _, pid := range pids {
					p, err := process.NewProcess(int32(pid))
					if err != nil {
						return false
					}
					name, err := p.Name()
					if err != nil || name != "sleep" {
						return false
					}
				}
				return true
			}, time.Second, 50*time.Millisecond)
			for _, pid := range pids {
				group, err := syscall.Getpgid(pid)
				require.NoError(t, err)
				require.NotEqual(t, cmd.Process.Pid, group)
			}
			if cancelTerminal {
				wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"openpty-id"}}`))
				require.ErrorIs(t, context.Cause(ctx), context.Canceled)
				select {
				case <-pc.cancelDone:
				default:
					t.Fatal("terminal did not receive cancellation")
				}
			}
			start := time.Now()
			pc.close()
			if cancelTerminal {
				assert.GreaterOrEqual(t, time.Since(start), commandcancel.GracePeriod, "TERM is ignored and cancellation must reach KILL")
			}
			assert.NotContains(t, registry.active, "openpty-id")
			cancelled, survivors := pc.cancelState.Finish()
			assert.Equal(t, cancelTerminal, cancelled)
			assert.Empty(t, survivors)
			assert.Eventually(t, func() bool { return !ptyTestProcessAlive(pids[0]) }, time.Second, 50*time.Millisecond)
			if cancelTerminal {
				assert.Eventually(t, func() bool { return !ptyTestProcessAlive(pids[1]) }, time.Second, 50*time.Millisecond)
			} else {
				assert.True(t, ptyTestProcessAlive(pids[1]), "nohup must survive ordinary close")
			}
		})
	}
}

func ptyTestProcessAlive(pid int) bool {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}
	statuses, err := p.Status()
	return err == nil && !slices.Contains(statuses, process.Zombie)
}

func TestPtyBackgroundCancelClosesChannelAndUnregisters(t *testing.T) {
	closed := make(chan error, 1)
	peer := newWshServerWith(t, func(_ int, conn *websocket.Conn) { closed <- readUntilError(conn) })
	manager := NewTerminalManager(nil)
	wc := &WebsocketClient{}
	ctx, open := wc.cancellations.register(context.Background(), "open-background")
	ctx = context.WithValue(ctx, cancellationRegistryKey{}, &wc.cancellations)
	pc := NewPtyClient(protocol.CommandData{SessionID: "background-cancel", URL: peer.wsURL(), Shell: "/bin/bash", Rows: 24, Cols: 80}, nil, manager)
	pc.TrackCommand(ctx, "open-background")
	done := make(chan struct{})
	go func() { pc.RunPtyBackground(); close(done) }()
	t.Cleanup(func() {
		wc.cancellations.cancel("open-background")
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("terminal worker did not exit")
		}
	})
	require.Eventually(t, func() bool { return manager.Get(pc.sessionID) != nil }, 5*time.Second, 50*time.Millisecond)
	wc.cancellations.finish("open-background", open)
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"open-background"}}`))
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not stop the terminal worker")
	}
	assert.Nil(t, manager.Get(pc.sessionID))
	wc.cancellations.mu.Lock()
	assert.NotContains(t, wc.cancellations.active, "open-background")
	wc.cancellations.mu.Unlock()
	select {
	case err := <-closed:
		var closeErr *websocket.CloseError
		require.ErrorAs(t, err, &closeErr)
		assert.Equal(t, websocket.CloseNormalClosure, closeErr.Code, "terminal uses the existing per-session close handshake")
	case <-time.After(time.Second):
		t.Fatal("no per-session close report")
	}
}
