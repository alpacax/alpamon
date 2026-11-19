//go:build !windows

package runner

import (
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessLookupErrorsPreserveTracking(t *testing.T) {
	for _, failed := range []string{"members", "started", "group"} {
		t.Run(failed, func(t *testing.T) {
			leader := startSession(t, "sleep", "60")
			sid := leader.Process.Pid
			session := OwnedSession{SID: sid, StartedAt: processStartedAt(sid)}
			require.NotZero(t, session.StartedAt)
			pinSession(session)
			t.Cleanup(func() { unpinSession(session) })
			table := systemProcessTable()
			switch failed {
			case "members":
				table.members = func(int) ([]int, error) { return nil, syscall.EACCES }
			case "started":
				table.started = func(int) (int64, error) { return 0, syscall.EACCES }
			case "group":
				table.pgid = func(int) (int, error) { return 0, syscall.EACCES }
			}
			_, err := ownedSessionStatusWithTable(session, table)
			assert.ErrorIs(t, err, syscall.EACCES)
			control := newProcessControl(nil).(*groupProcessControl)
			control.table = table
			_, err = control.Stop(wsID, OwnedWork{Sessions: []OwnedSession{session}})
			assert.ErrorIs(t, err, syscall.EACCES)
			_, err = control.End(wsID, OwnedWork{Sessions: []OwnedSession{session}})
			assert.ErrorIs(t, err, syscall.EACCES)
			sessionPins.mu.Lock()
			_, pinned := sessionPins.m[keyOf(session)]
			sessionPins.mu.Unlock()
			assert.True(t, pinned)
		})
	}
}

func TestSessionObserverRetriesTemporaryReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session := OwnedSession{SID: 900001, StartedAt: 100}
		pin := &sessionPin{members: map[int]int64{session.SID: 100}, stop: make(chan struct{}), done: make(chan struct{})}
		sessionPins.mu.Lock()
		sessionPins.m[keyOf(session)] = pin
		sessionPins.mu.Unlock()
		defer unpinSession(session)
		starts, lists := 0, 0
		table := sessionProcessTable{
			started: func(pid int) (int64, error) {
				starts++
				if starts == 1 {
					return 0, syscall.EACCES
				}
				if pid == session.SID {
					return 100, nil
				}
				return 101, nil
			},
			members: func(int) ([]int, error) {
				lists++
				if lists == 1 {
					return nil, syscall.EACCES
				}
				return []int{session.SID, session.SID + 1}, nil
			},
		}
		go observeSessionWithTable(session, pin, table, func(int) (procState, error) { return procRunning, nil })
		synctest.Wait()
		for range 3 {
			time.Sleep(50 * time.Millisecond)
			synctest.Wait()
			select {
			case <-pin.done:
				t.Fatal("the observer stopped after a temporary read failure")
			default:
			}
		}
		sessionPins.mu.Lock()
		started := pin.members[session.SID+1]
		sessionPins.mu.Unlock()
		assert.Equal(t, int64(101), started)
		unpinSession(session)
		<-pin.done
	})
}

func TestProcessInventoryBoundsMetadataReads(t *testing.T) {
	session := OwnedSession{SID: 910001, StartedAt: 100, Kind: ownedKindCommand, CommandID: "cmd-inventory"}
	t.Cleanup(func() { unpinSession(session) })
	pids := make([]int, workSessionInventoryLimit+2)
	for i := range pids {
		pids[i] = session.SID + i
	}
	control := newProcessControl(nil).(*groupProcessControl)
	control.table = sessionProcessTable{
		members: func(int) ([]int, error) { return pids, nil },
		started: func(int) (int64, error) { return 100, nil },
		pgid:    func(pid int) (int, error) { return pid, nil },
	}
	control.readState = func(int) (procState, error) { return procRunning, nil }
	reads := 0
	control.readArgs = func(int) ([]string, error) { reads++; return []string{"sleep", "60"}, nil }
	entries, err := control.Inventory(OwnedWork{Sessions: []OwnedSession{session}})
	require.NoError(t, err)
	require.Len(t, entries, workSessionInventoryLimit+1)
	assert.Equal(t, workSessionInventoryLimit, reads)
	assert.Equal(t, WorkSessionProcess{Kind: session.Kind, CommandID: session.CommandID, PID: pids[workSessionInventoryLimit]}, entries[workSessionInventoryLimit])
}

func TestSessionRegistrationRetriesTemporaryReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session := OwnedSession{SID: 930001, StartedAt: 100}
		defer unpinSession(session)
		lists := 0
		table := sessionProcessTable{
			members: func(int) ([]int, error) {
				lists++
				if lists == 1 {
					return nil, syscall.EACCES
				}
				return []int{session.SID, session.SID + 1}, nil
			},
			started: func(int) (int64, error) { return 100, nil },
		}
		pinSessionWithTable(session, table, func(int) (procState, error) { return procRunning, nil })
		synctest.Wait()
		sessionPins.mu.Lock()
		pin := sessionPins.m[keyOf(session)]
		sessionPins.mu.Unlock()
		require.NotNil(t, pin)
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		sessionPins.mu.Lock()
		started := pin.members[session.SID+1]
		sessionPins.mu.Unlock()
		assert.Equal(t, int64(100), started)
		unpinSession(session)
		<-pin.done
	})
}

func TestTerminationKeepsItsInitialMembershipBoundary(t *testing.T) {
	session := OwnedSession{SID: 920001, StartedAt: 100}
	child := session.SID + 1
	sessionPins.mu.Lock()
	sessionPins.m[keyOf(session)] = &sessionPin{members: map[int]int64{child: 101}}
	sessionPins.mu.Unlock()
	t.Cleanup(func() { unpinSession(session) })
	table := sessionProcessTable{
		members: func(int) ([]int, error) { return []int{child}, nil },
		started: func(int) (int64, error) { return 101, nil },
		pgid:    func(int) (int, error) { return child, nil },
	}
	members, err := terminationSessionMembers(session, map[int]commandcancel.SessionMember{session.SID: {StartedAt: 100, PGID: session.SID}}, func(int) (procState, error) { return procRunning, nil }, table)
	require.NoError(t, err)
	assert.Nil(t, members)
}

func TestProcessObservationRechecksAnEmptyResult(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		session := OwnedSession{SID: 940001, StartedAt: 100}
		sessionPins.mu.Lock()
		sessionPins.m[keyOf(session)] = &sessionPin{members: map[int]int64{session.SID: 100}}
		sessionPins.mu.Unlock()
		t.Cleanup(func() { unpinSession(session) })
		lists := 0
		table := sessionProcessTable{
			members: func(int) ([]int, error) {
				lists++
				if lists == 1 {
					if filtered {
						return []int{session.SID}, nil
					}
					return nil, nil
				}
				return []int{session.SID + 1}, nil
			},
			started: func(int) (int64, error) { return 100, nil },
		}
		_, err := observedSessionMembers(session, func(int) (procState, error) { return procZombie, nil }, table)
		assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
		sessionPins.mu.Lock()
		_, pinned := sessionPins.m[keyOf(session)]
		sessionPins.mu.Unlock()
		assert.True(t, pinned)
	}
}
