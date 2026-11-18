//go:build !windows

package runner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stopActionID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

// inventoryLog records posted inventories.
type inventoryLog struct {
	mu      sync.Mutex
	reports []WorkSessionProcessInventory
}

func (l *inventoryLog) post(inventory WorkSessionProcessInventory) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reports = append(l.reports, inventory)
}

func (l *inventoryLog) last(t *testing.T) WorkSessionProcessInventory {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	require.NotEmpty(t, l.reports)
	return l.reports[len(l.reports)-1]
}

func stopFrame(t *testing.T, revision uint64) []byte {
	t.Helper()
	frame, err := json.Marshal(map[string]any{"query": "control", "data": map[string]any{
		"type": "work_session_stop_processes", "protocol_version": 1, "client_id": "server-1",
		"work_session_id": wsID, "action_id": stopActionID, "revision": fmt.Sprint(revision),
	}})
	require.NoError(t, err)
	return frame
}

// startSession starts a session leader the way the executor starts a
// governed command and reaps it in the background.
func startSession(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not available", name)
	}
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	require.NoError(t, cmd.Start())
	sid := cmd.Process.Pid
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_, _, _ = commandcancel.TerminateSession(sid, 0)
		<-done
	})
	return cmd
}

func sessionMembers(t *testing.T, sid int, count int) []int {
	t.Helper()
	var members []int
	require.Eventually(t, func() bool {
		members = nil
		for _, member := range ownedMembers([]OwnedSession{{SID: sid}}) {
			members = append(members, member.pid)
		}
		return len(members) == count
	}, 5*time.Second, 20*time.Millisecond)
	return members
}

func pgids(t *testing.T, pids []int) []int {
	t.Helper()
	var groups []int
	for _, pid := range pids {
		pgid, err := syscall.Getpgid(pid)
		require.NoError(t, err)
		groups = append(groups, pgid)
	}
	slices.Sort(groups)
	return slices.Compact(groups)
}

func requireState(t *testing.T, want procState, pids ...int) {
	t.Helper()
	for _, pid := range pids {
		assert.Eventually(t, func() bool {
			state, err := processState(pid)
			return err == nil && state == want
		}, 5*time.Second, 20*time.Millisecond, "pid %d", pid)
	}
}

func newProcessRegistry(server *fakeControlServer, inventories *inventoryLog, cancel func(string)) *WorkSessionRegistry {
	r := newTestRegistry(server)
	control := newProcessControl(cancel).(*groupProcessControl)
	control.grace = 300 * time.Millisecond
	r.processes = control
	r.sessionAlive = ownedSessionAlive
	r.postInventory = inventories.post
	return r
}

func TestStopSuspendsEveryOwnedGroupAndResumeContinuesOnlyThem(t *testing.T) {
	server := &fakeControlServer{}
	inventories := &inventoryLog{}
	r := newProcessRegistry(server, inventories, nil)
	cc := &ControlClient{workSessions: r}

	// A running command whose child made its own process group, as a
	// job-control shell does for a background job.
	running := startSession(t, "perl", "-e", `if (fork() == 0) { setpgrp(0, 0); sleep 60; exit } sleep 60`)
	runningPIDs := sessionMembers(t, running.Process.Pid, 2)
	require.Len(t, pgids(t, runningPIDs), 2)
	// A finished command that left a child behind in its group.
	finished := startSession(t, "sh", "-c", "sleep 60 & exit 0")
	var leftover []int
	require.Eventually(t, func() bool {
		leftover = sessionMembers(t, finished.Process.Pid, 1)
		return leftover[0] != finished.Process.Pid
	}, 5*time.Second, 20*time.Millisecond, "the command finishes and its child lives on")
	// Work the session does not own.
	unrelated := startSession(t, "sleep", "60")

	r.trackProcess(wsID, ownedKindCommand, "cmd-running", running.Process.Pid)
	r.trackProcess(wsID, ownedKindCommand, "cmd-finished", finished.Process.Pid)

	cc.HandleMessage(pauseFrame(t, 1))
	requireState(t, procRunning, slices.Concat(runningPIDs, leftover)...)
	paused := inventories.last(t)
	assert.Equal(t, wsID, paused.WorkSessionID)
	assert.Len(t, paused.Processes, 3)

	cc.HandleMessage(stopFrame(t, 1))
	result := server.lastResult(t)
	assert.Equal(t, controlResultConfirmed, result.Result)
	assert.Equal(t, stopActionID, result.ActionID)
	assert.Equal(t, uint32(2), result.AffectedTrees)
	requireState(t, procStopped, slices.Concat(runningPIDs, leftover)...)
	requireState(t, procRunning, unrelated.Process.Pid)

	stopped := inventories.last(t)
	require.Len(t, stopped.Processes, 3)
	for _, entry := range stopped.Processes {
		assert.Equal(t, processStopped, entry.State)
		assert.Equal(t, ownedKindCommand, entry.Kind)
		assert.NotEmpty(t, entry.StartedAt)
		assert.NotEmpty(t, entry.Args)
	}

	cc.HandleMessage(resumeFrame(t, 2))
	assert.Equal(t, controlResultConfirmed, server.lastResult(t).Result)
	requireState(t, procRunning, slices.Concat(runningPIDs, leftover)...)
	resumed := inventories.last(t)
	assert.Equal(t, "2", fmt.Sprint(uint64(resumed.Revision)))
	for _, entry := range resumed.Processes {
		assert.Equal(t, processRunning, entry.State)
	}
}

func TestResumeLeavesAGroupStopNeverStopped(t *testing.T) {
	server := &fakeControlServer{}
	r := newProcessRegistry(server, &inventoryLog{}, nil)
	cc := &ControlClient{workSessions: r}

	stoppedElsewhere := startSession(t, "sleep", "60")
	stoppedByStop := startSession(t, "sleep", "60")
	r.trackProcess(wsID, ownedKindTerminal, "cmd-open", stoppedElsewhere.Process.Pid)
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", stoppedByStop.Process.Pid)

	cc.HandleMessage(pauseFrame(t, 1))
	require.NoError(t, syscall.Kill(-stoppedElsewhere.Process.Pid, syscall.SIGSTOP))
	requireState(t, procStopped, stoppedElsewhere.Process.Pid)
	cc.HandleMessage(stopFrame(t, 1))
	requireState(t, procStopped, stoppedByStop.Process.Pid)

	cc.HandleMessage(resumeFrame(t, 2))
	requireState(t, procRunning, stoppedByStop.Process.Pid)
	time.Sleep(100 * time.Millisecond)
	requireState(t, procStopped, stoppedElsewhere.Process.Pid)
}

func TestEndContinuesThenTerminatesEveryOwnedSession(t *testing.T) {
	server := &fakeControlServer{}
	var cancelled []string
	r := newProcessRegistry(server, &inventoryLog{}, func(id string) { cancelled = append(cancelled, id) })
	cc := &ControlClient{workSessions: r}

	stubborn := startSession(t, "perl", "-e", `$SIG{TERM} = "IGNORE"; sleep 60`)
	marker := filepath.Join(t.TempDir(), "term")
	stopped := startSession(t, "perl", "-e", `$SIG{TERM} = sub { open(my $f, ">", $ARGV[0]); exit 0 }; sleep 60`, marker)
	server.set(workSessionActive, 0)
	release, err := r.admit(t.Context(), attribution(0), "cmd-stubborn")
	require.NoError(t, err)
	defer release()
	r.trackProcess(wsID, ownedKindCommand, "cmd-stubborn", stubborn.Process.Pid)
	r.trackProcess(wsID, ownedKindCommand, "cmd-stopped", stopped.Process.Pid)

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopFrame(t, 1))
	requireState(t, procStopped, stubborn.Process.Pid, stopped.Process.Pid)

	cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
	ended := server.lastResult(t)
	assert.Equal(t, controlResultConfirmed, ended.Result)
	assert.Equal(t, uint32(2), ended.AffectedTrees)
	assert.Empty(t, ended.Survivors)
	assert.Equal(t, []string{"cmd-stubborn"}, cancelled, "End reuses the command cancel for running commands")
	assert.False(t, ownedSessionAlive(OwnedSession{SID: stubborn.Process.Pid}), "KILL follows the ignored TERM")
	assert.False(t, ownedSessionAlive(OwnedSession{SID: stopped.Process.Pid}))
	assert.FileExists(t, marker, "a stopped process is continued, so it acts on TERM")
}

func TestReconnectWhilePausedReportsTheInventory(t *testing.T) {
	server := &fakeControlServer{}
	inventories := &inventoryLog{}
	r := newProcessRegistry(server, inventories, nil)
	cc := &ControlClient{workSessions: r}

	leader := startSession(t, "sleep", "60")
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", leader.Process.Pid)
	cc.HandleMessage(pauseFrame(t, 1))
	before := len(inventories.reports)

	server.set(workSessionPaused, 1)
	r.reconcileAll(t.Context())
	assert.Len(t, inventories.reports, before+1)
	assert.Equal(t, leader.Process.Pid, inventories.last(t).Processes[0].PID)
}
