//go:build !windows

package runner

import (
	"encoding/json"
	"fmt"
	"os"
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

// liveMembers lists the processes of session sid that are not zombies.
func liveMembers(t *testing.T, sid int) []int {
	t.Helper()
	pids, err := commandcancel.SessionMembers(sid)
	require.NoError(t, err)
	var live []int
	for _, pid := range pids {
		if state, err := processState(pid); err == nil && state != procZombie {
			live = append(live, pid)
		}
	}
	return live
}

func sessionMembers(t *testing.T, sid int, count int) []int {
	t.Helper()
	var members []int
	require.Eventually(t, func() bool {
		members = liveMembers(t, sid)
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

// requireHeldSignals skips a test that stops or resumes real processes on a
// host where Stop and Resume are unsupported.
func requireHeldSignals(t *testing.T) {
	t.Helper()
	if !commandcancel.PinnedSignalsHeld() {
		t.Skip("this host cannot hold a process through signal delivery")
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
	requireHeldSignals(t)
	server := &fakeControlServer{}
	inventories := &inventoryLog{}
	r := newProcessRegistry(server, inventories, nil)
	cc := &ControlClient{workSessions: r}

	// A running command whose child made its own process group, as a
	// job-control shell does for a background job.
	running := startSession(t, "perl", "-e", `if (fork() == 0) { setpgrp(0, 0); sleep 60; exit } sleep 60`)
	runningPIDs := sessionMembers(t, running.Process.Pid, 2)
	require.Eventually(t, func() bool {
		firstGroup, err := syscall.Getpgid(runningPIDs[0])
		if err != nil {
			return false
		}
		secondGroup, err := syscall.Getpgid(runningPIDs[1])
		return err == nil && firstGroup != secondGroup
	}, 5*time.Second, 20*time.Millisecond, "the child creates its own process group")
	require.Len(t, pgids(t, runningPIDs), 2)
	// A finished command that left a child behind in its group. It is
	// tracked while its leader runs and released once it finishes, as the
	// executor does.
	server.set(workSessionActive, 0)
	release, err := r.admit(t.Context(), attribution(0), "cmd-finished")
	require.NoError(t, err)
	finished := startSession(t, "sh", "-c", "sleep 60 & sleep 0.5; exit 0")
	r.trackProcess(wsID, ownedKindCommand, "cmd-finished", finished.Process.Pid)
	var leftover []int
	require.Eventually(t, func() bool {
		leftover = sessionMembers(t, finished.Process.Pid, 1)
		return leftover[0] != finished.Process.Pid
	}, 5*time.Second, 20*time.Millisecond, "the command finishes and its child lives on")
	release()
	// Work the session does not own.
	unrelated := startSession(t, "sleep", "60")

	r.trackProcess(wsID, ownedKindCommand, "cmd-running", running.Process.Pid)

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
	requireHeldSignals(t)
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
	requireHeldSignals(t)
	server := &fakeControlServer{}
	var cancelled []string
	r := newProcessRegistry(server, &inventoryLog{}, func(id string) { cancelled = append(cancelled, id) })
	cc := &ControlClient{workSessions: r}

	dir := t.TempDir()
	stubbornReady := filepath.Join(dir, "stubborn-ready")
	stoppedReady := filepath.Join(dir, "stopped-ready")
	marker := filepath.Join(dir, "term")
	stubborn := startSession(t, "perl", "-e", `$SIG{TERM} = "IGNORE"; open(my $ready, ">", $ARGV[0]) or die $!; close($ready); sleep 60`, stubbornReady)
	stopped := startSession(t, "perl", "-e", `$SIG{TERM} = sub { open(my $f, ">", $ARGV[0]); exit 0 }; open(my $ready, ">", $ARGV[1]) or die $!; close($ready); sleep 60`, marker, stoppedReady)
	require.Eventually(t, func() bool {
		if _, err := os.Stat(stubbornReady); err != nil {
			return false
		}
		_, err := os.Stat(stoppedReady)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "both TERM handlers are installed before Stop")
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
	assert.Empty(t, liveMembers(t, stubborn.Process.Pid), "KILL follows the ignored TERM")
	assert.Empty(t, liveMembers(t, stopped.Process.Pid))
	assert.FileExists(t, marker, "a stopped process is continued, so it acts on TERM")
}

func TestReconnectToActiveContinuesWhatAStopSuspended(t *testing.T) {
	requireHeldSignals(t)
	server := &fakeControlServer{}
	r := newProcessRegistry(server, &inventoryLog{}, nil)
	cc := &ControlClient{workSessions: r}
	leader := startSession(t, "sleep", "60")
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", leader.Process.Pid)

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopFrame(t, 1))
	requireState(t, procStopped, leader.Process.Pid)

	// The Resume was missed while the control socket was down.
	server.set(workSessionActive, 2)
	r.reconcileAll(t.Context())
	assert.True(t, r.inputAllowed(wsID))
	requireState(t, procRunning, leader.Process.Pid)
}

func TestEndSendsNoKillOnceNothingPinsTheSession(t *testing.T) {
	server := &fakeControlServer{}
	r := newProcessRegistry(server, &inventoryLog{}, nil)
	cc := &ControlClient{workSessions: r}

	// On TERM the leader leaves a TERM-ignoring child no check has seen and
	// exits, so nothing proves the SID still names this session.
	dir := t.TempDir()
	ready, marker := filepath.Join(dir, "ready"), filepath.Join(dir, "child")
	leader := startSession(t, "perl", "-e", `$SIG{TERM} = sub { if (fork() == 0) { $SIG{TERM} = "IGNORE"; open(my $f, ">", $ARGV[1]); close($f); sleep 60; exit } exit 0 }; open(my $f, ">", $ARGV[0]); close($f); sleep 60`, ready, marker)
	sid := leader.Process.Pid
	require.Eventually(t, func() bool { _, err := os.Stat(ready); return err == nil }, 5*time.Second, 20*time.Millisecond)
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", sid)

	cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
	ended := server.lastResult(t)
	require.FileExists(t, marker)
	child := sessionMembers(t, sid, 1)
	assert.NotEqual(t, sid, child[0])
	assert.Equal(t, controlResultFailed, ended.Result)
	assert.Equal(t, errorCodeSurvivors, ended.Error)
	require.Len(t, ended.Survivors, 1)
	assert.Equal(t, child[0], ended.Survivors[0].PID, "a process End could not prove is reported, not killed")
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

func TestSessionIdentityFailsClosed(t *testing.T) {
	leader := startSession(t, "sleep", "60")
	sid := leader.Process.Pid
	started := processStartedAt(sid)
	require.NotZero(t, started)

	assert.NotEmpty(t, ownedMembers([]OwnedSession{{SID: sid, StartedAt: started}}), "the recorded leader is ours")
	assert.Empty(t, ownedMembers([]OwnedSession{{SID: sid}}), "an unknown start time proves nothing")
	assert.Empty(t, ownedMembers([]OwnedSession{{SID: sid, StartedAt: started - 1000}}), "a PID now naming another process is not ours")
}

func TestSessionWhoseLeaderExitedIsOwnedOnlyThroughAPin(t *testing.T) {
	finished := startSession(t, "sh", "-c", "sleep 60 & sleep 0.5; exit 0")
	sid := finished.Process.Pid
	session := OwnedSession{Kind: ownedKindCommand, CommandID: "cmd-1", SID: sid, StartedAt: processStartedAt(sid)}
	require.NotZero(t, session.StartedAt)
	require.Eventually(t, func() bool {
		members := liveMembers(t, sid)
		return len(members) == 1 && members[0] != sid
	}, 5*time.Second, 20*time.Millisecond)

	assert.Empty(t, ownedMembers([]OwnedSession{session}), "with its leader gone, nothing pins the SID to this session")

	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newProcessRegistry(server, &inventoryLog{}, nil)
	release, err := r.admit(t.Context(), attribution(0), "cmd-2")
	require.NoError(t, err)
	r.trackProcess(wsID, ownedKindCommand, "cmd-2", sid)
	release()
	_, tracked := r.sessions[wsID]
	assert.False(t, tracked, "a session tracked after its leader exited is never owned")
}

func TestResumeDoesNotContinueARetainedGroupThatChangedIdentity(t *testing.T) {
	requireHeldSignals(t)
	server := &fakeControlServer{}
	r := newProcessRegistry(server, &inventoryLog{}, nil)
	cc := &ControlClient{workSessions: r}
	leader := startSession(t, "sleep", "60")
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", leader.Process.Pid)

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopFrame(t, 1))
	requireState(t, procStopped, leader.Process.Pid)

	// The group a Stop retained no longer has the member it was pinned by.
	control := r.processes.(*groupProcessControl)
	control.mu.Lock()
	for _, group := range control.stopped[wsID] {
		for pid := range group.members {
			group.members[pid]--
		}
	}
	control.mu.Unlock()

	cc.HandleMessage(resumeFrame(t, 2))
	time.Sleep(100 * time.Millisecond)
	requireState(t, procStopped, leader.Process.Pid)
}

func TestStopAndResumeReportUnsupportedWhereSignalsCannotBeHeld(t *testing.T) {
	server := &fakeControlServer{}
	r := newProcessRegistry(server, &inventoryLog{}, nil)
	r.processes.(*groupProcessControl).heldSignals = false
	cc := &ControlClient{workSessions: r}

	owned := startSession(t, "sleep", "60")
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", owned.Process.Pid)

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopFrame(t, 1))
	stopped := server.lastResult(t)
	assert.Equal(t, controlResultUnsupported, stopped.Result)
	assert.Empty(t, stopped.Error)
	time.Sleep(100 * time.Millisecond)
	requireState(t, procRunning, owned.Process.Pid)

	require.NoError(t, syscall.Kill(owned.Process.Pid, syscall.SIGSTOP))
	requireState(t, procStopped, owned.Process.Pid)
	cc.HandleMessage(resumeFrame(t, 2))
	assert.Equal(t, controlResultUnsupported, server.lastResult(t).Result)
	time.Sleep(100 * time.Millisecond)
	requireState(t, procStopped, owned.Process.Pid)

	cc.HandleMessage(controlFrame(t, "work_session_end", 3, "ended", "human_end"))
	ended := server.lastResult(t)
	assert.Equal(t, controlResultConfirmed, ended.Result, "End stays best-effort termination")
	assert.Empty(t, liveMembers(t, owned.Process.Pid))
}
