//go:build !windows

package runner

import (
	"syscall"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnknownSessionStartLeavesProcessActionsUnconfirmed(t *testing.T) {
	for _, memberOffset := range []int{0, 1} {
		session := OwnedSession{SID: 950001 + memberOffset, CommandID: "cmd-unknown-start"}
		startReads := 0
		table := sessionProcessTable{
			members: func(int) ([]int, error) { return []int{session.SID + memberOffset}, nil },
			started: func(int) (int64, error) { startReads++; return 100, nil },
		}
		alive, err := ownedSessionStatusWithTable(session, table)
		assert.False(t, alive)
		assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
		control := newProcessControl(nil).(*groupProcessControl)
		control.table = table
		control.heldSignals = true // lookup fails closed before any signal, on every host
		_, err = control.Stop(wsID, OwnedWork{Sessions: []OwnedSession{session}})
		assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
		_, err = control.End(wsID, OwnedWork{Sessions: []OwnedSession{session}})
		assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
		assert.Zero(t, startReads, "later observations cannot replace an unrecorded start time")
		sessionPins.mu.Lock()
		_, pinned := sessionPins.m[keyOf(session)]
		sessionPins.mu.Unlock()
		assert.False(t, pinned)
	}
}

func TestUnknownSessionStartPreservesLookupErrors(t *testing.T) {
	session := OwnedSession{SID: 960001}
	table := sessionProcessTable{members: func(int) ([]int, error) { return nil, syscall.EACCES }}
	_, err := ownedSessionStatusWithTable(session, table)
	assert.ErrorIs(t, err, syscall.EACCES)
	control := newProcessControl(nil).(*groupProcessControl)
	control.table = table
	control.heldSignals = true // lookup fails closed before any signal, on every host
	_, err = control.Stop(wsID, OwnedWork{Sessions: []OwnedSession{session}})
	assert.ErrorIs(t, err, syscall.EACCES)
	_, err = control.End(wsID, OwnedWork{Sessions: []OwnedSession{session}})
	assert.ErrorIs(t, err, syscall.EACCES)
}

func TestUnknownSessionStartRequiresConfirmedAbsence(t *testing.T) {
	for _, result := range []string{"empty", "member", "error"} {
		t.Run(result, func(t *testing.T) {
			session := OwnedSession{SID: 970001}
			reads := 0
			table := sessionProcessTable{members: func(int) ([]int, error) {
				reads++
				if reads == 1 || result == "empty" {
					return nil, nil
				}
				if result == "error" {
					return nil, syscall.EACCES
				}
				return []int{session.SID}, nil
			}}
			members, err := refreshSessionPinWithTable(session, nil, table)
			switch result {
			case "empty":
				require.NoError(t, err)
				assert.NotNil(t, members)
				assert.Empty(t, members)
			case "member":
				assert.ErrorIs(t, err, commandcancel.ErrSessionUnverified)
			case "error":
				assert.ErrorIs(t, err, syscall.EACCES)
			}
			assert.Equal(t, 2, reads)
		})
	}
}
