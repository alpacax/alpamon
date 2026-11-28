package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPruneRetainsUncertainProcessStatus(t *testing.T) {
	r := newTestRegistry(&fakeControlServer{})
	owned := OwnedSession{SID: 4242, StartedAt: 1, CommandID: "cmd-1"}
	r.session(wsID).processes[owned.SID] = owned
	r.sessionStatus = func(OwnedSession) (bool, error) { return false, errors.New("unavailable") }
	r.pruneProcesses(wsID)
	assert.Equal(t, owned, r.sessions[wsID].processes[owned.SID])
}

func TestControlDisconnectFencesTrackedSession(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	release, err := r.admit(t.Context(), attribution(0), "cmd-1")
	require.NoError(t, err)
	defer release()
	(&ControlClient{workSessions: r}).Close()
	assert.False(t, r.inputAllowed(wsID))
}

func TestControlStateReadHonorsCancellation(t *testing.T) {
	var requests int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"state":"active","revision":"1"}`))
	}))
	defer origin.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := readWorkSessionControlState(ctx, &scheduler.Session{BaseURL: origin.URL, Client: origin.Client()}, wsID)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, requests)
}

func TestStopWaitsForAuthoritativeState(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}
	cc.HandleMessage(pauseFrame(t, 1))
	r.mu.Lock()
	r.sessions[wsID].known = false
	r.mu.Unlock()
	server.set(workSessionPaused, 1)
	before := server.resultCount()
	cc.HandleMessage(stopProcessesFrame(t, 1))
	require.Eventually(t, func() bool { return server.resultCount() > before }, time.Second, time.Millisecond)
	assert.Empty(t, server.lastResult(t).Error)
	assert.Equal(t, controlResultUnsupported, server.lastResult(t).Result)
}

func TestReconcileReadDoesNotBlockAnotherSessionsControl(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	started, finish := make(chan struct{}), make(chan struct{})
	r.readState = func(context.Context, string) (WorkSessionSnapshot, error) {
		close(started)
		<-finish
		return WorkSessionSnapshot{State: workSessionActive, Revision: protocol.Uint64String(0)}, nil
	}
	done := make(chan struct{})
	go func() { _ = r.reconcile(t.Context(), wsID); close(done) }()
	<-started
	controlled := make(chan struct{})
	go func() { (&ControlClient{workSessions: r}).HandleMessage(pauseFrame(t, 1)); close(controlled) }()
	select {
	case <-controlled:
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "control handling waited for an HTTP read")
	}
	close(finish)
	<-done
	<-controlled
	assert.False(t, r.inputAllowed(wsID))
}

func TestReconcileRetriesSupersededRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTestRegistry(&fakeControlServer{})
		started, finish := make(chan struct{}), make(chan struct{})
		reads := 0
		r.readState = func(context.Context, string) (WorkSessionSnapshot, error) {
			reads++
			if reads == 1 {
				close(started)
				<-finish
			}
			return WorkSessionSnapshot{State: workSessionActive}, nil
		}
		first := make(chan error, 1)
		go func() { first <- r.reconcile(t.Context(), wsID) }()
		<-started
		ids := r.invalidateAll()
		done := make(chan struct{})
		go func() { r.reconcileIDs(t.Context(), ids); close(done) }()
		synctest.Wait()
		close(finish)
		<-done
		assert.ErrorIs(t, <-first, errWorkSessionStale)
		assert.Equal(t, 2, reads)
		assert.True(t, r.inputAllowed(wsID))
	})
}

func TestReconcileRetriesOlderSnapshot(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 2)
	r := newTestRegistry(server)
	release, err := r.admit(t.Context(), attribution(2), "cmd-1")
	require.NoError(t, err)
	defer release()
	reads := 0
	r.readState = func(context.Context, string) (WorkSessionSnapshot, error) {
		reads++
		return WorkSessionSnapshot{State: workSessionActive, Revision: protocol.Uint64String(min(reads, 2))}, nil
	}
	r.reconcileAll(t.Context())
	assert.Equal(t, 2, reads)
	assert.True(t, r.inputAllowed(wsID))
}
