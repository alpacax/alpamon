package runner

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expiryEndControl struct {
	recordingControl
	ended     chan struct{}
	continues atomic.Int32
}

func (c *expiryEndControl) Continue(string, OwnedWork) (ProcessEffect, error) {
	c.continues.Add(1)
	return ProcessEffect{}, nil
}

func (c *expiryEndControl) End(id string, owned OwnedWork) (ProcessEffect, error) {
	effect, err := c.recordingControl.End(id, owned)
	c.ended <- struct{}{}
	return effect, err
}

func TestPausedExpiryDoesNotInventResume(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeControlServer{}
		r := newTestRegistry(server)
		control := &expiryEndControl{ended: make(chan struct{}, 4)}
		r.processes = control
		cc := &ControlClient{workSessions: r}
		cc.HandleMessage(pauseFrame(t, 1))
		cc.HandleMessage(stopProcessesFrame(t, 1))
		server.set(workSessionEnded, 1)
		keep := false
		server.state.EndProcesses = &keep
		require.NoError(t, r.reconcile(t.Context(), wsID))
		r.mu.Lock()
		s := r.sessions[wsID]
		r.mu.Unlock()
		defer stopCleanupLoop(r, s)
		synctest.Wait()
		assert.Zero(t, control.continues.Load())
		require.NoError(t, r.reconcile(t.Context(), wsID))
		synctest.Wait()
		assert.Zero(t, control.continues.Load())
		assert.False(t, r.inputAllowed(wsID))
	})
}

func TestHigherExpiryRevisionRecoversMissedResume(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeControlServer{}
		r := newTestRegistry(server)
		control := &expiryEndControl{ended: make(chan struct{}, 4)}
		r.processes = control
		cc := &ControlClient{workSessions: r}
		cc.HandleMessage(pauseFrame(t, 1))
		cc.HandleMessage(stopProcessesFrame(t, 1))
		server.set(workSessionEnded, 2)
		keep := false
		server.state.EndProcesses = &keep
		require.NoError(t, r.reconcile(t.Context(), wsID))
		r.mu.Lock()
		s := r.sessions[wsID]
		r.mu.Unlock()
		defer stopCleanupLoop(r, s)
		synctest.Wait()
		assert.Equal(t, int32(1), control.continues.Load())
		assert.Zero(t, control.endCount())
		assert.False(t, r.inputAllowed(wsID))
	})
}

func TestLaterEndedSnapshotRecoversMissedResume(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeControlServer{}
		r := newTestRegistry(server)
		control := &expiryEndControl{ended: make(chan struct{}, 4)}
		r.processes = control
		cc := &ControlClient{workSessions: r}
		cc.HandleMessage(pauseFrame(t, 1))
		cc.HandleMessage(stopProcessesFrame(t, 1))
		keep := false
		for _, revision := range []uint64{1, 2} {
			server.set(workSessionEnded, revision)
			server.state.EndProcesses = &keep
			require.NoError(t, r.reconcile(t.Context(), wsID))
			synctest.Wait()
		}
		r.mu.Lock()
		s := r.sessions[wsID]
		r.mu.Unlock()
		defer stopCleanupLoop(r, s)
		assert.Equal(t, int32(1), control.continues.Load())
		server.set(workSessionEnded, 1)
		require.NoError(t, r.reconcile(t.Context(), wsID))
		synctest.Wait()
		assert.Zero(t, control.endCount())
		assert.False(t, r.inputAllowed(wsID))
	})
}

func TestEndedSnapshotCanRequireProcessTerminationLater(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, revision := range []uint64{1, 2} {
			server := &fakeControlServer{}
			server.set(workSessionEnded, 1)
			keep := false
			server.state.EndProcesses = &keep
			r := newTestRegistry(server)
			control := &expiryEndControl{ended: make(chan struct{}, 4)}
			r.processes = control
			require.NoError(t, r.reconcile(t.Context(), wsID))
			r.mu.Lock()
			s := r.sessions[wsID]
			r.mu.Unlock()
			defer stopCleanupLoop(r, s)
			server.set(workSessionEnded, revision)
			require.NoError(t, r.reconcile(t.Context(), wsID))
			select {
			case <-control.ended:
			case <-time.After(time.Second):
				assert.Fail(t, "the authoritative ended snapshot did not terminate processes")
			}
			synctest.Wait()
			assert.Equal(t, 1, control.endCount())
			require.NoError(t, r.reconcile(t.Context(), wsID))
			synctest.Wait()
			assert.Equal(t, 1, control.endCount())
			assert.False(t, r.inputAllowed(wsID))
		}
	})
}
