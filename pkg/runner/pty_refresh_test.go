//go:build !windows

package runner

import (
	"bufio"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// startPtyShell runs script as a PTY session leader, the way Websh starts the user's shell.
func startPtyShell(t *testing.T, script string) (*PtyClient, *bufio.Reader) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	ptmx, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // background jobs the script left in its group
		_ = ptmx.Close()
		_ = cmd.Wait()
	})

	out := bufio.NewReader(ptmx)
	waitForLine(t, out, "ready")
	return &PtyClient{cmd: cmd, ptmx: ptmx, sessionID: "refresh-test"}, out
}

func waitForLine(t *testing.T, out *bufio.Reader, want string) {
	t.Helper()
	found := make(chan struct{})
	go func() {
		for {
			line, err := out.ReadString('\n')
			if strings.TrimSpace(line) == want {
				close(found)
				return
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-found:
	case <-time.After(5 * time.Second):
		t.Fatalf("PTY never printed %q", want)
	}
}

func TestRefreshSignalsForegroundGroupOfLiveShell(t *testing.T) {
	pc, out := startPtyShell(t, `trap 'echo winch' WINCH; echo ready; while :; do sleep 0.1; done`)

	err := pc.Refresh()

	require.NoError(t, err)
	waitForLine(t, out, "winch")
}

func TestRefreshDoesNotSignalCallerGroupAfterShellExits(t *testing.T) {
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	t.Cleanup(func() { signal.Stop(winch) })
	// A background job that ignores SIGHUP keeps the PTY open after the shell exits, so the
	// session outlives its foreground process group.
	pc, _ := startPtyShell(t, `trap "" HUP; sleep 30 & echo ready; exit 0`)
	_, err := pc.cmd.Process.Wait()
	require.NoError(t, err)
	fg, err := unix.IoctlGetInt(int(pc.ptmx.Fd()), unix.TIOCGPGRP)
	require.NoError(t, err)
	require.Zero(t, fg, "the exited shell should leave the PTY without a foreground group")

	err = pc.Refresh()

	assert.ErrorContains(t, err, "no foreground process group")
	select {
	case <-winch:
		t.Fatal("Refresh sent SIGWINCH to the caller's own process group")
	case <-time.After(300 * time.Millisecond):
	}
}
