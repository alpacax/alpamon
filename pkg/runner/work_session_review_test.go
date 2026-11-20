package runner

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blockingContinueControl struct {
	recordingControl
	started chan struct{}
	finish  chan struct{}
}

func (c *blockingContinueControl) Continue(string, OwnedWork) (ProcessEffect, error) {
	close(c.started)
	<-c.finish
	return ProcessEffect{}, nil
}

func TestWorkReleaseWaitsForProcessActions(t *testing.T) {
	for _, kind := range []string{ownedKindCommand, ownedKindTerminal} {
		t.Run(kind, func(t *testing.T) {
			func(t *testing.T) {
				server := &fakeControlServer{}
				server.set(workSessionActive, 0)
				r := newTestRegistry(server)
				release, err := r.admit(t.Context(), attribution(0), "cmd-1")
				require.NoError(t, err)
				if kind == ownedKindTerminal {
					unregister := r.registerTerminal(wsID, "terminal-1", "cmd-1")
					release()
					release = unregister
				}

				r.actions.Lock()
				done := make(chan struct{})
				go func() { release(); close(done) }()
				// Mutex waits do not advance a synctest clock.
				select {
				case <-done:
					assert.Fail(t, "work was released before the process action finished")
				case <-time.After(50 * time.Millisecond):
				}
				commands, terminals := r.owned(wsID)
				if kind == ownedKindCommand {
					assert.Equal(t, []string{"cmd-1"}, commands)
				} else {
					assert.Equal(t, []string{"cmd-1"}, terminals)
				}
				r.actions.Unlock()
				<-done
				commands, terminals = r.owned(wsID)
				assert.Empty(t, commands)
				assert.Empty(t, terminals)
			}(t)
		})
	}
}

func TestReconcileDoesNotOverwriteAConcurrentPause(t *testing.T) {
	func(t *testing.T) {
		server := &fakeControlServer{}
		server.set(workSessionActive, 0)
		r := newTestRegistry(server)
		release, err := r.admit(t.Context(), attribution(0), "cmd-1")
		require.NoError(t, err)
		defer release()

		reading, finishRead := make(chan struct{}), make(chan struct{})
		r.readState = func(context.Context, string) (WorkSessionSnapshot, error) {
			close(reading)
			<-finishRead
			return WorkSessionSnapshot{State: workSessionActive, Revision: 1}, nil
		}
		reconciled := make(chan struct{})
		go func() { r.reconcileAll(t.Context()); close(reconciled) }()
		<-reading
		paused := make(chan struct{})
		frame := pauseFrame(t, 1)
		go func() { (&ControlClient{workSessions: r}).HandleMessage(frame); close(paused) }()
		// Mutex waits need a real-clock bound.
		select {
		case <-paused:
		case <-time.After(50 * time.Millisecond):
		}
		close(finishRead)
		<-reconciled
		<-paused

		assert.False(t, r.inputAllowed(wsID))
	}(t)
}

func TestStopRejectsUnsupportedProtocolBeforeDuplicateOrStateChecks(t *testing.T) {
	for _, version := range []int{0, 2} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			server := &fakeControlServer{}
			r := newTestRegistry(server)
			cc := &ControlClient{workSessions: r}
			cc.HandleMessage(pauseFrame(t, 1))
			cc.HandleMessage(stopProcessesFrame(t, 1))
			var frame struct {
				Data workSessionControl `json:"data"`
			}
			require.NoError(t, json.Unmarshal(stopProcessesFrame(t, 1), &frame))
			frame.Data.ProtocolVersion = version
			raw, err := json.Marshal(frame.Data)
			require.NoError(t, err)
			r.handleControl(raw)
			result := server.lastResult(t)
			assert.Equal(t, controlResultUnsupported, result.Result)
			assert.Equal(t, "invalid_message", result.Error)
			assert.Equal(t, workSessionPaused, result.State)
			assert.NotNil(t, result.Survivors)
		})
	}
}

func TestReconciledEndFollowsInFlightResume(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	release, err := r.admit(t.Context(), attribution(0), "cmd-1")
	require.NoError(t, err)
	defer release()
	control := &blockingContinueControl{started: make(chan struct{}), finish: make(chan struct{})}
	r.processes = control
	cc := &ControlClient{workSessions: r}
	cc.HandleMessage(pauseFrame(t, 1))
	frame := resumeFrame(t, 2)
	resumed := make(chan struct{})
	go func() { cc.HandleMessage(frame); close(resumed) }()
	<-control.started
	server.set(workSessionEnded, 3)
	reconciled := make(chan struct{})
	go func() { r.reconcileAll(t.Context()); close(reconciled) }()
	select {
	case <-reconciled:
	case <-time.After(50 * time.Millisecond):
	}
	close(control.finish)
	<-resumed
	<-reconciled
	assert.Eventually(t, func() bool { return control.endCount() == 1 }, time.Second, time.Millisecond)
	assert.False(t, r.inputAllowed(wsID))
}

func TestControlTransitionReceipts(t *testing.T) {
	server := &fakeControlServer{readErr: errors.New("unavailable")}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}
	cc.HandleMessage(pauseFrame(t, 1))
	for range 2 {
		cc.HandleMessage(resumeFrame(t, 1))
		result := server.lastResult(t)
		assert.Equal(t, controlResultFailed, result.Result)
		assert.Equal(t, "conflict", result.Error)
		assert.False(t, r.inputAllowed(wsID))
	}
	release, err := r.admit(t.Context(), protocol.WorkSession{ID: wsID, Revision: 1}, "cmd-1")
	if release != nil {
		defer release()
	}
	assert.ErrorIs(t, err, errWorkSessionStateUnknown)
}

func TestControlSnapshotReceipts(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionPaused, 1)
	r := newTestRegistry(server)
	require.NoError(t, r.reconcile(t.Context(), wsID))
	server.readErr = errors.New("unavailable")
	cc := &ControlClient{workSessions: r}
	for range 2 {
		cc.HandleMessage(resumeFrame(t, 1))
		result := server.lastResult(t)
		assert.Equal(t, controlResultFailed, result.Result)
		assert.Equal(t, "conflict", result.Error)
		assert.False(t, r.inputAllowed(wsID))
	}
	release, err := r.admit(t.Context(), protocol.WorkSession{ID: wsID, Revision: 1}, "cmd-1")
	if release != nil {
		defer release()
	}
	assert.ErrorIs(t, err, errWorkSessionStateUnknown)
}

func TestControlReceiptReconciliation(t *testing.T) {
	for _, recovery := range []string{"read", "higher revision"} {
		t.Run(recovery, func(t *testing.T) {
			server := &fakeControlServer{}
			server.set(workSessionActive, 1)
			r := newTestRegistry(server)
			require.NoError(t, r.reconcile(t.Context(), wsID))
			cc := &ControlClient{workSessions: r}
			for _, frame := range [][]byte{pauseFrame(t, 1), resumeFrame(t, 1)} {
				cc.HandleMessage(frame)
				result := server.lastResult(t)
				assert.Equal(t, controlResultFailed, result.Result)
				assert.Equal(t, "conflict", result.Error)
				assert.False(t, r.inputAllowed(wsID))
			}
			if recovery == "read" {
				require.NoError(t, r.reconcile(t.Context(), wsID))
			} else {
				cc.HandleMessage(resumeFrame(t, 2))
			}
			assert.True(t, r.inputAllowed(wsID))
		})
	}
}

func TestControlTerminalReceiptReconciliation(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	survivor := WorkSessionSurvivor{CommandID: "cmd-1", PID: 4242, PGID: 4242}
	control := &recordingControl{endEffects: []ProcessEffect{
		{Survivors: []WorkSessionSurvivor{survivor}},
		{Survivors: []WorkSessionSurvivor{}},
	}, endErr: errProcessSurvivors}
	r.processes = control
	r.sessionAlive = func(OwnedSession) bool { return true }
	r.trackProcess(wsID, ownedKindCommand, "cmd-1", 4242)
	cc := &ControlClient{workSessions: r}
	end := controlFrame(t, "work_session_end", 2, workSessionEnded, "human_end")
	cc.HandleMessage(end)
	require.Equal(t, 1, control.endCount())
	original := server.lastResult(t)
	cc.HandleMessage(resumeFrame(t, 2))
	server.set(workSessionEnded, 2)
	require.NoError(t, r.reconcile(t.Context(), wsID))
	cc.HandleMessage(end)
	assert.Equal(t, 1, control.endCount())
	assert.Equal(t, original, server.lastResult(t))
}

func TestControlSnapshotUpdatesReceipts(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}
	cc.HandleMessage(pauseFrame(t, 1))
	server.set(workSessionActive, 1)
	require.NoError(t, r.reconcile(t.Context(), wsID))
	cc.HandleMessage(resumeFrame(t, 1))
	result := server.lastResult(t)
	assert.Equal(t, controlResultConfirmed, result.Result)
	assert.Equal(t, workSessionActive, result.State)
	assert.True(t, r.inputAllowed(wsID))
}
