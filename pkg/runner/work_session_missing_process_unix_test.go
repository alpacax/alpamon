//go:build !windows

package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMissingProcessRecordRemainsNonOwning(t *testing.T) {
	for _, started := range []int64{0, 100} {
		session := OwnedSession{SID: 980001, StartedAt: started, missing: true}
		lookups := 0
		table := sessionProcessTable{
			members: func(int) ([]int, error) { lookups++; return nil, nil },
			started: func(int) (int64, error) { lookups++; return started, nil },
			pgid:    func(int) (int, error) { lookups++; return session.SID, nil },
		}
		readState := func(int) (procState, error) { lookups++; return procRunning, nil }
		pinSessionWithTable(session, table, readState)
		t.Cleanup(func() { unpinSession(session) })
		sessionPins.mu.Lock()
		_, pinned := sessionPins.m[keyOf(session)]
		sessionPins.mu.Unlock()
		assert.False(t, pinned)
		members, err := refreshSessionPinWithTable(session, nil, table)
		require.NoError(t, err)
		assert.NotNil(t, members)
		assert.Empty(t, members)
		alive, err := ownedSessionStatusWithTable(session, table)
		require.NoError(t, err)
		assert.False(t, alive)
		cancelled := false
		control := newProcessControl(func(string) { cancelled = true }).(*groupProcessControl)
		control.table = table
		control.readState = readState
		for _, action := range []func(string, OwnedWork) (ProcessEffect, error){control.Stop, control.Continue, control.End} {
			effect, err := action(wsID, OwnedWork{Sessions: []OwnedSession{session}})
			require.NoError(t, err)
			assert.Zero(t, effect.AffectedTrees)
			assert.Empty(t, effect.Survivors)
		}
		assert.False(t, cancelled)
		assert.Zero(t, lookups)
	}
}
