package runner

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndedSessionPrunesFinishedProcessesWithoutInventory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTestRegistry(&fakeControlServer{})
		var phase atomic.Int32
		var checks atomic.Int32
		r.sessionStatus = func(OwnedSession) (bool, error) {
			checks.Add(1)
			switch phase.Load() {
			case 1:
				return false, errors.New("process lookup unavailable")
			case 2:
				return false, nil
			default:
				return true, nil
			}
		}
		owned := OwnedSession{CommandID: "cmd-cleanup", SID: 940001, StartedAt: 1}
		s := r.session(wsID)
		s.processes[owned.SID] = owned
		(&ControlClient{workSessions: r}).HandleMessage(controlFrame(t, "work_session_end", 1, workSessionEnded, "human_end"))
		defer stopCleanupLoop(r, s)
		receipt := *s.lastResult

		time.Sleep(workSessionInventoryInterval)
		synctest.Wait()
		r.mu.Lock()
		assert.Equal(t, owned, s.processes[owned.SID])
		r.mu.Unlock()

		phase.Store(1)
		time.Sleep(workSessionInventoryInterval)
		synctest.Wait()
		r.mu.Lock()
		assert.Equal(t, owned, s.processes[owned.SID], "uncertain liveness keeps the process tracked")
		r.mu.Unlock()

		phase.Store(2)
		time.Sleep(workSessionInventoryInterval)
		synctest.Wait()
		r.mu.Lock()
		assert.Empty(t, s.processes)
		assert.Nil(t, s.stopInventory)
		assert.Same(t, s, r.sessions[wsID])
		assert.Equal(t, receipt, *s.lastResult)
		r.mu.Unlock()
		assert.False(t, r.inputAllowed(wsID))
		stoppedChecks := checks.Load()
		time.Sleep(3 * workSessionInventoryInterval)
		synctest.Wait()
		assert.Equal(t, stoppedChecks, checks.Load(), "cleanup stops after the last owned process exits")
	})
}

func TestEndedSessionCleanupAllowsBoundedRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTestRegistry(&fakeControlServer{})
		var alive atomic.Bool
		var reports atomic.Int32
		alive.Store(true)
		r.processes = listingControl{}
		r.sessionStatus = func(OwnedSession) (bool, error) { return alive.Load(), nil }
		r.postInventory = func(WorkSessionProcessInventory) { reports.Add(1) }
		s := r.session(wsID)
		s.processes[940002] = OwnedSession{SID: 940002, StartedAt: 1}
		(&ControlClient{workSessions: r}).HandleMessage(controlFrame(t, "work_session_end", 1, workSessionEnded, "human_end"))
		defer stopCleanupLoop(r, s)
		r.mu.Lock()
		for i := range workSessionEndedLimit {
			id := fmt.Sprintf("ended-%d", i)
			r.session(id).state = workSessionEnded
			r.markEnded(id)
		}
		retained := r.sessions[wsID]
		r.mu.Unlock()
		require.Same(t, s, retained)

		alive.Store(false)
		time.Sleep(workSessionInventoryInterval)
		synctest.Wait()
		r.mu.Lock()
		r.session("ended-last").state = workSessionEnded
		r.markEnded("ended-last")
		assert.NotContains(t, r.sessions, wsID)
		assert.Len(t, r.sessions, workSessionEndedLimit)
		assert.Len(t, r.ended, workSessionEndedLimit)
		r.mu.Unlock()
		assert.Zero(t, reports.Load(), "ended sessions do not post process inventories")
	})
}

func stopCleanupLoop(r *WorkSessionRegistry, s *trackedWorkSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.stopInventory != nil {
		close(s.stopInventory)
		s.stopInventory = nil
	}
}
