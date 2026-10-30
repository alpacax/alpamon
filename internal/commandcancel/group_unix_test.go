//go:build !windows

package commandcancel

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminationReportsSurvivorsAfterEscalation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var signals []syscall.Signal
		start := time.Now()
		survivors, err := terminate(func(signal syscall.Signal) error { signals = append(signals, signal); return nil }, func() ([]int, error) { return []int{42, 43}, nil }, GracePeriod)
		require.NoError(t, err)
		assert.Equal(t, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}, signals)
		assert.Equal(t, []int{42, 43}, survivors)
		assert.Equal(t, GracePeriod+100*time.Millisecond, time.Since(start))
	})
}

func TestTerminationDetectsRealSurvivor(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	// A failed signal leaves a real member for the OS-backed scan to find.
	survivors, err := terminate(func(syscall.Signal) error { return syscall.EPERM }, func() ([]int, error) { return GroupMembers(cmd.Process.Pid) }, time.Millisecond)
	assert.ErrorIs(t, err, syscall.EPERM)
	assert.Contains(t, survivors, cmd.Process.Pid)
}

func TestTerminationRejectsReservedIDs(t *testing.T) {
	// Check the guards before calling them: a regression must never signal PID 1.
	source, err := os.ReadFile("group_unix.go")
	require.NoError(t, err)
	require.True(t, strings.Contains(string(source), "if pgid <= 1 {"))
	require.True(t, strings.Contains(string(source), "if sid <= 1 {"))
	for _, id := range []int{-1, 0, 1} {
		_, sent, err := TerminateGroup(id, 0)
		assert.Error(t, err)
		assert.False(t, sent)
		_, sent, err = TerminateSession(id, 0)
		assert.Error(t, err)
		assert.False(t, sent)
		assert.Error(t, HangupSession(id))
	}
}

func TestTerminationPollsEvery50Milliseconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var scans []time.Time
		_, err := terminate(func(syscall.Signal) error { return nil }, func() ([]int, error) {
			scans = append(scans, time.Now())
			return []int{42}, nil
		}, 100*time.Millisecond)
		require.NoError(t, err)
		require.Len(t, scans, 6) // three grace scans and three post-KILL scans
		assert.Equal(t, 50*time.Millisecond, scans[1].Sub(scans[0]))
	})
}
