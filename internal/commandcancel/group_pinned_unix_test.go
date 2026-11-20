//go:build !windows

package commandcancel

import (
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
		sid:    func(int) (int, error) { return 42, nil },
		pgid:   func(pid int) (int, error) { return pid, nil },
		signal: func(pgid int, _ syscall.Signal) error { signalled = append(signalled, pgid); return nil },
	}
	groups, err := signalPinnedSessionGroups(42, map[int]SessionMember{43: {StartedAt: 100, PGID: 43}, 44: {StartedAt: 100, PGID: 44}}, syscall.SIGSTOP, ops)
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
		sid:     func(int) (int, error) { return 42, nil },
		pgid:    func(int) (int, error) { return 43, nil },
		signal:  func(pgid int, _ syscall.Signal) error { signals = append(signals, pgid); return nil },
	}
	groups, err := signalPinnedSessionGroups(42, map[int]SessionMember{43: {StartedAt: 100, PGID: 43}}, syscall.SIGCONT, ops)
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
