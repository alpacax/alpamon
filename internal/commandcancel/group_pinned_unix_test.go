//go:build !windows

package commandcancel

import (
	"errors"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPinnedGroupsCheckCurrentMembership(t *testing.T) {
	for _, changed := range []string{"start", "session", "group", "read"} {
		t.Run(changed, func(t *testing.T) {
			calls := 0
			ops := pinnedSignalOps{
				started: func(int) (int64, error) { return 100, nil },
				sid:     func(int) (int, error) { return 42, nil },
				pgid:    func(int) (int, error) { return 43, nil },
				signal:  func(int, syscall.Signal) error { calls++; return nil },
			}
			switch changed {
			case "start":
				reads := 0
				ops.started = func(int) (int64, error) {
					reads++
					if reads > 1 {
						return 101, nil
					}
					return 100, nil
				}
			case "session":
				reads := 0
				ops.sid = func(int) (int, error) {
					reads++
					if reads > 1 {
						return 44, nil
					}
					return 42, nil
				}
			case "group":
				reads := 0
				ops.pgid = func(int) (int, error) {
					reads++
					if reads > 1 {
						return 44, nil
					}
					return 43, nil
				}
			case "read":
				ops.started = func(int) (int64, error) { return 0, syscall.EACCES }
			}
			groups, err := signalPinnedSessionGroups(42, map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}, syscall.SIGSTOP, ops)
			assert.Error(t, err)
			assert.Empty(t, groups)
			assert.Zero(t, calls)
		})
	}
}

func TestPinnedGroupsUseEachGroupsMember(t *testing.T) {
	var signalled []int
	ops := pinnedSignalOps{
		started: func(pid int) (int64, error) {
			if pid == 44 {
				return 101, nil
			}
			return 100, nil
		},
		sid:    func(int) (int, error) { return 43, nil },
		pgid:   func(pid int) (int, error) { return pid, nil },
		signal: func(pgid int, _ syscall.Signal) error { signalled = append(signalled, pgid); return nil },
		leader: heldLeaderFake(43),
	}
	groups, err := signalPinnedSessionGroups(43, map[int]SessionMember{43: {StartedAt: 100, PGID: 43}, 44: {StartedAt: 100, PGID: 44}}, syscall.SIGSTOP, ops)
	assert.ErrorIs(t, err, ErrSessionUnverified)
	assert.Equal(t, []int{43}, groups)
	assert.Equal(t, []int{-43}, signalled)
}

func TestPinnedTerminationRetainsLookupErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checks := 0
		var signals []syscall.Signal
		survivors, sent, err := terminatePinnedSession(42, 100*time.Millisecond, func() (map[int]SessionMember, error) {
			checks++
			if checks > 1 {
				return nil, syscall.EACCES
			}
			return map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}, nil
		}, func(_ int, _ map[int]SessionMember, sig syscall.Signal) ([]int, error) {
			signals = append(signals, sig)
			return []int{43}, nil
		}, func(int) ([]int, error) { return []int{43}, nil })
		assert.ErrorIs(t, err, syscall.EACCES)
		assert.True(t, sent)
		assert.Equal(t, []int{43}, survivors)
		assert.Equal(t, []syscall.Signal{syscall.SIGTERM}, signals)
	})
}

func TestPinnedGroupsSignalVerifiedMembers(t *testing.T) {
	var signals []int
	ops := pinnedSignalOps{
		started: func(int) (int64, error) { return 100, nil },
		sid:     func(int) (int, error) { return 43, nil },
		pgid:    func(int) (int, error) { return 43, nil },
		signal:  func(pgid int, _ syscall.Signal) error { signals = append(signals, pgid); return nil },
		leader:  heldLeaderFake(43),
	}
	groups, err := signalPinnedSessionGroups(43, map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}, syscall.SIGCONT, ops)
	require.NoError(t, err)
	assert.Equal(t, []int{43}, groups)
	assert.Equal(t, []int{-43}, signals)
}

func TestProcessMatchingReturnsLookupErrors(t *testing.T) {
	members, err := matchingProcesses(func(int) (bool, error) { return false, syscall.EACCES })
	assert.ErrorIs(t, err, syscall.EACCES)
	assert.Empty(t, members)
	members, err = matchingProcesses(func(int) (bool, error) { return false, syscall.ESRCH })
	require.NoError(t, err)
	assert.Empty(t, members)
}

// fakeKernel stands in for the process table and pidfds. Each PID maps to
// the generation of the process that holds it; a pidfd refers to the
// generation that held the PID when it was opened.
type fakeKernel struct {
	starts    map[int]int64
	pgids     map[int]int
	fds       map[int]int64
	fdPIDs    map[int]int
	delivered []int
	groups    []int
	afterRead func(reads int)
	reads     int
	openErr   error
	held      map[int]bool
}

func newFakeKernel(members map[int]SessionMember) *fakeKernel {
	k := &fakeKernel{starts: map[int]int64{}, pgids: map[int]int{}, fds: map[int]int64{}, fdPIDs: map[int]int{}, held: map[int]bool{}}
	for pid, member := range members {
		k.starts[pid], k.pgids[pid] = member.StartedAt, member.PGID
	}
	return k
}

// exitAndReuse ends the process holding pid and hands the PID and its group
// to an unrelated process.
func (k *fakeKernel) exitAndReuse(pid int, started int64) { k.starts[pid] = started }

func (k *fakeKernel) ops() pinnedSignalOps {
	return pinnedSignalOps{
		started: func(pid int) (int64, error) {
			k.reads++
			started, ok := k.starts[pid]
			if k.afterRead != nil {
				k.afterRead(k.reads)
			}
			if !ok {
				return 0, syscall.ESRCH
			}
			return started, nil
		},
		sid:    func(int) (int, error) { return 42, nil },
		pgid:   func(pid int) (int, error) { return k.pgids[pid], nil },
		signal: func(pgid int, _ syscall.Signal) error { k.groups = append(k.groups, pgid); return nil },
		leader: func(pid int, signal func() error) (bool, error) {
			if !k.held[pid] {
				return false, nil
			}
			return true, signal()
		},
		pidfd: &pidfdOps{
			open: func(pid int) (int, error) {
				if k.openErr != nil {
					return -1, k.openErr
				}
				started, ok := k.starts[pid]
				if !ok {
					return -1, syscall.ESRCH
				}
				fd := len(k.fds) + 100
				k.fds[fd], k.fdPIDs[fd] = started, pid
				return fd, nil
			},
			send: func(fd int, _ syscall.Signal) error {
				pid := k.fdPIDs[fd]
				if k.starts[pid] != k.fds[fd] {
					return syscall.ESRCH
				}
				k.delivered = append(k.delivered, pid)
				return nil
			},
			close: func(int) error { return nil },
		},
	}
}

func TestHeldSignalsReachEachVerifiedProcessNotItsGroup(t *testing.T) {
	members := map[int]SessionMember{43: {StartedAt: 100, PGID: 43}, 44: {StartedAt: 100, PGID: 43}}
	kernel := newFakeKernel(members)
	groups, err := signalPinnedSessionGroups(42, members, syscall.SIGSTOP, kernel.ops())
	require.NoError(t, err)
	assert.Equal(t, []int{43}, groups)
	assert.Equal(t, []int{43, 44}, kernel.delivered)
	assert.Empty(t, kernel.groups, "no signal goes to a PGID")
}

func TestHeldSignalsVerifyAfterTheProcessIsHeld(t *testing.T) {
	members := map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}
	kernel := newFakeKernel(members)
	// The member passes the check made before its pidfd is opened, then
	// exits, and its PID is reused before the check made through the pidfd.
	kernel.afterRead = func(reads int) {
		if reads == 1 {
			kernel.exitAndReuse(43, 200)
		}
	}
	groups, err := signalPinnedSessionGroups(42, members, syscall.SIGSTOP, kernel.ops())
	assert.ErrorIs(t, err, ErrSessionUnverified)
	assert.Empty(t, groups)
	assert.Empty(t, kernel.delivered)
	assert.Empty(t, kernel.groups)
}

func TestHeldSignalsDoNotFollowAReusedPID(t *testing.T) {
	members := map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}
	kernel := newFakeKernel(members)
	// The member passes the last check, then exits and its PID and group are
	// reused before the signal is delivered.
	kernel.afterRead = func(reads int) {
		if reads == 2 {
			kernel.exitAndReuse(43, 200)
		}
	}
	groups, err := signalPinnedSessionGroups(42, members, syscall.SIGKILL, kernel.ops())
	require.NoError(t, err, "a member that exited is gone, not a failure")
	assert.Empty(t, groups)
	assert.Empty(t, kernel.delivered, "the signal stays with the exited process")
	assert.Empty(t, kernel.groups, "no signal goes to the reused group")
}

func TestHeldSignalsRequireAHostThatHoldsProcesses(t *testing.T) {
	members := map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}
	t.Run("no pidfd", func(t *testing.T) {
		kernel := newFakeKernel(members)
		ops := kernel.ops()
		ops.pidfd = nil
		groups, err := signalHeldSessionMembers(42, members, syscall.SIGSTOP, ops)
		assert.ErrorIs(t, err, ErrSignalNotHeld)
		assert.ErrorIs(t, err, errors.ErrUnsupported)
		assert.Empty(t, groups)
		assert.Empty(t, kernel.groups)
	})
	t.Run("ENOSYS", func(t *testing.T) {
		kernel := newFakeKernel(members)
		kernel.openErr = syscall.ENOSYS
		groups, err := signalHeldSessionMembers(42, members, syscall.SIGSTOP, kernel.ops())
		assert.ErrorIs(t, err, ErrSignalNotHeld)
		assert.Empty(t, groups)
		assert.Empty(t, kernel.delivered)
		assert.Empty(t, kernel.groups)
	})
}

func TestSignalsWithoutPidfdReachOnlyAHeldLeadersGroup(t *testing.T) {
	members := map[int]SessionMember{42: {StartedAt: 100, PGID: 42}, 43: {StartedAt: 100, PGID: 42}, 44: {StartedAt: 100, PGID: 44}}
	kernel := newFakeKernel(members)
	kernel.held[42] = true
	ops := kernel.ops()
	ops.pidfd = nil
	groups, err := signalPinnedSessionGroups(42, members, syscall.SIGTERM, ops)
	require.NoError(t, err, "a group without a held leader is left to be reported")
	assert.Equal(t, []int{42}, groups)
	assert.Equal(t, []int{-42}, kernel.groups, "only the group the unreaped leader pins is signalled")
}

func TestSignalsWithoutPidfdSendNothingOnceTheLeaderIsReaped(t *testing.T) {
	members := map[int]SessionMember{43: {StartedAt: 100, PGID: 42}}
	kernel := newFakeKernel(members)
	ops := kernel.ops()
	ops.pidfd = nil
	groups, err := signalPinnedSessionGroups(42, members, syscall.SIGKILL, ops)
	require.NoError(t, err)
	assert.Empty(t, groups)
	assert.Empty(t, kernel.groups)
}

func TestReapLeaderWaitsForASignalInFlight(t *testing.T) {
	const pid = 990001
	HoldLeader(pid)
	reaped := make(chan struct{})
	sent, err := withHeldLeader(pid, func() error {
		go func() { _ = ReapLeader(pid, func() error { close(reaped); return nil }) }()
		select {
		case <-reaped:
			t.Error("the leader was reaped while a signal relied on it")
		case <-time.After(50 * time.Millisecond):
		}
		return nil
	})
	require.NoError(t, err)
	assert.True(t, sent)
	<-reaped
	sent, err = withHeldLeader(pid, func() error { t.Error("signalled a reaped leader"); return nil })
	require.NoError(t, err)
	assert.False(t, sent)
}

func TestUnheldLeaderIsNeverSignalled(t *testing.T) {
	sent, err := withHeldLeader(990002, func() error { t.Error("signalled a leader alpamon does not hold"); return nil })
	require.NoError(t, err)
	assert.False(t, sent)
	require.NoError(t, ReapLeader(990002, func() error { return nil }))
}

// heldLeaderFake holds only pid unreaped.
func heldLeaderFake(pid int) func(int, func() error) (bool, error) {
	return func(leader int, signal func() error) (bool, error) {
		if leader != pid {
			return false, nil
		}
		return true, signal()
	}
}
