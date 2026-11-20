//go:build !windows

package runner

import (
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpiryAfterMissedResumeContinuesStoppedGroups(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	inventories := &inventoryLog{}
	r := newProcessRegistry(server, inventories, nil)
	release, err := r.admit(t.Context(), attribution(0), "cmd-1")
	require.NoError(t, err)
	defer release()
	leader := startSession(t, "sleep", "60")
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", leader.Process.Pid)
	cc := &ControlClient{workSessions: r}
	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopProcessesFrame(t, 1))
	requireState(t, procStopped, leader.Process.Pid)
	inventories.mu.Lock()
	before := len(inventories.reports)
	inventories.mu.Unlock()
	cc.Close()
	keep := false
	server.mu.Lock()
	server.state = WorkSessionSnapshot{State: workSessionEnded, Revision: protocol.Uint64String(3), EndProcesses: &keep}
	server.mu.Unlock()
	r.reconcileAll(t.Context())
	assert.Eventually(t, func() bool {
		state, err := processState(leader.Process.Pid)
		return err == nil && state == procRunning
	}, time.Second, 10*time.Millisecond)
	r.actions.Lock()
	allowed := r.inputAllowed(wsID)
	r.actions.Unlock()
	inventories.mu.Lock()
	assert.Len(t, inventories.reports, before)
	inventories.mu.Unlock()
	assert.False(t, allowed)
	_, err = r.admit(t.Context(), attribution(3), "cmd-2")
	assert.ErrorIs(t, err, errWorkSessionEnded)
}
