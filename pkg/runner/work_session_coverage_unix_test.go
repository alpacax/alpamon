//go:build !windows

package runner

import (
	"os"
	"syscall"
	"testing"
	"testing/synctest"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessControlReportsIncompleteCoverage(t *testing.T) {
	session := OwnedSession{SID: 900005, StartedAt: 100, CommandID: "command"}
	child := session.SID + 1
	sessionPins.mu.Lock()
	sessionPins.m[keyOf(session)] = &sessionPin{members: map[int]int64{session.SID: 100, child: 101}}
	sessionPins.mu.Unlock()
	t.Cleanup(func() { unpinSession(session) })

	control := newProcessControl(nil).(*groupProcessControl)
	control.heldSignals = true
	control.table = sessionProcessTable{
		members: func(int) ([]int, error) { return nil, nil },
		started: func(int) (int64, error) { return 101, nil },
		sid:     func(int) (int, error) { return child, nil },
	}
	work := OwnedWork{Sessions: []OwnedSession{session}}
	_, err := control.Stop(wsID, work)
	assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
	_, err = control.End(wsID, work)
	assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
}

func TestStopReportsIncompleteCoverageAfterStoppingVerifiedMembers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session := OwnedSession{SID: 900009, StartedAt: 100, CommandID: "command"}
		child := session.SID + 1
		sessionPins.mu.Lock()
		sessionPins.m[keyOf(session)] = &sessionPin{members: map[int]int64{session.SID: 100, child: 101}}
		sessionPins.mu.Unlock()
		t.Cleanup(func() { unpinSession(session) })

		control := newProcessControl(nil).(*groupProcessControl)
		control.heldSignals = true
		control.table = sessionProcessTable{
			members: func(int) ([]int, error) { return []int{session.SID}, nil },
			started: func(pid int) (int64, error) {
				if pid == session.SID {
					return session.StartedAt, nil
				}
				return 101, nil
			},
			sid:  func(pid int) (int, error) { return pid, nil },
			pgid: func(pid int) (int, error) { return pid, nil },
		}
		states := map[int]procState{session.SID: procRunning, child: procRunning}
		control.readState = func(pid int) (procState, error) { return states[pid], nil }
		control.signalMembers = func(sid int, members map[int]commandcancel.SessionMember, sig syscall.Signal) ([]int, error) {
			assert.Equal(t, session.SID, sid)
			assert.Equal(t, syscall.SIGSTOP, sig)
			assert.Equal(t, map[int]commandcancel.SessionMember{
				session.SID: {StartedAt: session.StartedAt, PGID: session.SID},
			}, members)
			for pid := range members {
				states[pid] = procStopped
			}
			return []int{session.SID}, nil
		}

		effect, err := control.Stop(wsID, OwnedWork{Sessions: []OwnedSession{session}})
		assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
		assert.Equal(t, controlResultFailed, processResult(err))
		assert.Equal(t, uint32(1), effect.AffectedTrees)
		assert.Equal(t, procStopped, states[session.SID])
		assert.Equal(t, procRunning, states[child])
	})
}

func TestProcessControlTracksChildrenOutsideTheSession(t *testing.T) {
	session := OwnedSession{SID: 900007, StartedAt: 100, CommandID: "command"}
	child := session.SID + 1
	t.Cleanup(func() { unpinSession(session) })
	childAlive := true
	table := sessionProcessTable{
		members: func(int) ([]int, error) { return []int{session.SID}, nil },
		started: func(pid int) (int64, error) {
			if pid == session.SID {
				return session.StartedAt, nil
			}
			if childAlive {
				return 101, nil
			}
			return 0, os.ErrNotExist
		},
		sid:  func(pid int) (int, error) { return pid, nil },
		pgid: func(pid int) (int, error) { return pid, nil },
		outsideChildren: func(sid int, parents map[int]int64) (map[int]int64, error) {
			assert.Equal(t, session.SID, sid)
			assert.Equal(t, map[int]int64{session.SID: session.StartedAt}, parents)
			return map[int]int64{child: 101}, nil
		},
	}
	_, err := observedSessionMembers(session, nil, table)
	assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)

	table.outsideChildren = nil
	_, err = ownedSessionStatusWithTable(session, table)
	assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)

	childAlive = false
	members, err := observedSessionMembers(session, func(int) (procState, error) { return procRunning, nil }, table)
	require.NoError(t, err)
	require.Contains(t, members, session.SID)
	assert.NotContains(t, members, child)
}
