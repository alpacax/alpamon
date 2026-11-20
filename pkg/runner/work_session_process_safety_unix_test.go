//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdoptSessionRejectsMembersWithoutAnObservedPin(t *testing.T) {
	leader := startSession(t, "sleep", "60")
	sid := leader.Process.Pid
	started := processStartedAt(sid)
	require.NotZero(t, started)
	session := OwnedSession{SID: sid, StartedAt: started - 1000}
	sessionPins.mu.Lock()
	sessionPins.m[keyOf(session)] = &sessionPin{members: map[int]int64{sid: session.StartedAt}}
	sessionPins.mu.Unlock()
	t.Cleanup(func() { unpinSession(session) })

	adoptSession(session)
	assert.Empty(t, ownedMembers([]OwnedSession{session}))
	control := newProcessControl(nil).(*groupProcessControl)
	effect, err := control.Stop(wsID, OwnedWork{Sessions: []OwnedSession{session}})
	require.NoError(t, err)
	assert.Zero(t, effect.AffectedTrees)
	requireState(t, procRunning, sid)
}

func TestPinSessionRetainsAChildObservedBeforeItsLeaderExited(t *testing.T) {
	finish := filepath.Join(t.TempDir(), "finish")
	leader := startSession(t, "sh", "-c", `sleep 60 & while [ ! -e "$1" ]; do sleep 0.01; done`, "sh", finish)
	sid := leader.Process.Pid
	session := OwnedSession{SID: sid, StartedAt: processStartedAt(sid)}
	require.NotZero(t, session.StartedAt)
	require.Eventually(t, func() bool { return len(liveMembers(t, sid)) >= 2 }, 5*time.Second, 20*time.Millisecond)
	pinSession(session)
	t.Cleanup(func() { unpinSession(session) })
	require.NoError(t, os.WriteFile(finish, nil, 0600))
	var child int
	require.Eventually(t, func() bool {
		members := liveMembers(t, sid)
		if len(members) != 1 || members[0] == sid {
			return false
		}
		child = members[0]
		return true
	}, 5*time.Second, 20*time.Millisecond)

	adoptSession(session)
	members := ownedMembers([]OwnedSession{session})
	require.Len(t, members, 1)
	assert.Equal(t, child, members[0].pid)
}

func TestStopReportsOwnedMembersWhoseStateCannotBeRead(t *testing.T) {
	leader := startSession(t, "sleep", "60")
	sid := leader.Process.Pid
	session := OwnedSession{CommandID: "cmd-unreadable", SID: sid, StartedAt: processStartedAt(sid)}
	require.NotZero(t, session.StartedAt)
	pinSession(session)
	t.Cleanup(func() { unpinSession(session) })
	control := newProcessControl(nil).(*groupProcessControl)
	control.readState = func(int) (procState, error) { return procRunning, syscall.EACCES }

	effect, err := control.Stop(wsID, OwnedWork{Sessions: []OwnedSession{session}})
	assert.ErrorIs(t, err, syscall.EACCES)
	assert.ErrorIs(t, err, errProcessSurvivors)
	assert.Equal(t, uint32(1), effect.AffectedTrees)
	assert.Equal(t, []WorkSessionSurvivor{{CommandID: session.CommandID, PID: sid, PGID: sid}}, effect.Survivors)
	assert.NotEmpty(t, ownedMembers([]OwnedSession{session}), "unreadable state does not discard a proven identity")
}

func TestPinSessionObservesChildrenBornAfterTracking(t *testing.T) {
	dir := t.TempDir()
	spawn, finish, childFile := filepath.Join(dir, "spawn"), filepath.Join(dir, "finish"), filepath.Join(dir, "child")
	leader := startSession(t, "sh", "-c", `while [ ! -e "$1" ]; do sleep 0.01; done; sleep 60 & echo $! > "$3"; while [ ! -e "$2" ]; do sleep 0.01; done`, "sh", spawn, finish, childFile)
	sid := leader.Process.Pid
	session := OwnedSession{SID: sid, StartedAt: processStartedAt(sid)}
	require.NotZero(t, session.StartedAt)
	pinSession(session)
	t.Cleanup(func() { unpinSession(session) })
	require.NoError(t, os.WriteFile(spawn, nil, 0600))
	var child int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(childFile)
		if err != nil {
			return false
		}
		child, err = strconv.Atoi(strings.TrimSpace(string(data)))
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool {
		sessionPins.mu.Lock()
		defer sessionPins.mu.Unlock()
		pin := sessionPins.m[keyOf(session)]
		return pin != nil && pin.members[child] != 0
	}, 5*time.Second, 20*time.Millisecond, "the live leader proves a child discovered after tracking")
	require.NoError(t, os.WriteFile(finish, nil, 0600))
	require.Eventually(t, func() bool {
		members := liveMembers(t, sid)
		return len(members) == 1 && members[0] == child
	}, 5*time.Second, 20*time.Millisecond)

	adoptSession(session)
	members := ownedMembers([]OwnedSession{session})
	require.Len(t, members, 1)
	assert.Equal(t, child, members[0].pid)
}

func TestUnpinSessionStopsItsObserver(t *testing.T) {
	leader := startSession(t, "sleep", "60")
	sid := leader.Process.Pid
	session := OwnedSession{SID: sid, StartedAt: processStartedAt(sid)}
	require.NotZero(t, session.StartedAt)
	pinSession(session)
	t.Cleanup(func() { unpinSession(session) })
	sessionPins.mu.Lock()
	pin := sessionPins.m[keyOf(session)]
	sessionPins.mu.Unlock()
	require.NotNil(t, pin)
	require.NotNil(t, pin.done)

	unpinSession(session)
	select {
	case <-pin.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session observer did not stop")
	}
	assert.Nil(t, refreshSessionPin(session, pin), "a completed observation cannot restore an unpinned session")
	sessionPins.mu.Lock()
	_, pinned := sessionPins.m[keyOf(session)]
	sessionPins.mu.Unlock()
	assert.False(t, pinned)
}

func TestSessionObserverStopsAfterItsLeaderExits(t *testing.T) {
	leader := startSession(t, "sleep", "60")
	sid := leader.Process.Pid
	session := OwnedSession{SID: sid, StartedAt: processStartedAt(sid)}
	require.NotZero(t, session.StartedAt)
	pinSession(session)
	t.Cleanup(func() { unpinSession(session) })
	sessionPins.mu.Lock()
	pin := sessionPins.m[keyOf(session)]
	sessionPins.mu.Unlock()
	require.NotNil(t, pin)
	require.NotNil(t, pin.done)

	require.NoError(t, leader.Process.Signal(syscall.SIGTERM))
	select {
	case <-pin.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session observer did not stop after its leader exited")
	}
}
