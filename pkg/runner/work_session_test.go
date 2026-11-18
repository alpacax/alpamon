package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	wsID       = "11111111-1111-4111-8111-111111111111"
	transition = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa%d"
)

var wsNow = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

// fakeControlServer answers control-state reads and records posted results.
type fakeControlServer struct {
	mu      sync.Mutex
	state   WorkSessionSnapshot
	readErr error
	reads   int
	results []WorkSessionControlResult
}

func (s *fakeControlServer) read(_ context.Context, id string) (WorkSessionSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.readErr != nil {
		return WorkSessionSnapshot{}, s.readErr
	}
	return s.state, nil
}

func (s *fakeControlServer) post(result WorkSessionControlResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, result)
}

func (s *fakeControlServer) set(state string, revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = WorkSessionSnapshot{State: state, Revision: protocol.Uint64String(revision), ExpiresAt: wsNow.Add(time.Hour)}
}

func (s *fakeControlServer) lastResult(t *testing.T) WorkSessionControlResult {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.results)
	return s.results[len(s.results)-1]
}

func (s *fakeControlServer) resultCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}

func newTestRegistry(server *fakeControlServer) *WorkSessionRegistry {
	r := newWorkSessionRegistry(server.read, server.post)
	r.now = func() time.Time { return wsNow }
	return r
}

func attribution(revision uint64) protocol.WorkSession {
	return protocol.WorkSession{ID: wsID, Revision: revision, ExpiresAt: wsNow.Add(time.Hour)}
}

func controlFrame(t *testing.T, kind string, revision uint64, state, reason string) []byte {
	t.Helper()
	frame, err := json.Marshal(map[string]any{
		"query": "control",
		"data": map[string]any{
			"type":             kind,
			"protocol_version": 1,
			"client_id":        "server-1",
			"work_session_id":  wsID,
			"transition_id":    fmt.Sprintf(transition, revision),
			"revision":         fmt.Sprint(revision),
			"state":            state,
			"expires_at":       wsNow.Add(time.Hour).Format(time.RFC3339),
			"reason":           reason,
		},
	})
	require.NoError(t, err)
	return frame
}

func pauseFrame(t *testing.T, revision uint64) []byte {
	return controlFrame(t, "work_session_pause", revision, "paused", "critical_deny")
}

func resumeFrame(t *testing.T, revision uint64) []byte {
	return controlFrame(t, "work_session_resume", revision, "active", "human_resume")
}

func TestAdmitReadsControlStateBeforeTheFirstCommand(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)

	release, err := r.admit(context.Background(), attribution(0), "cmd-1")
	require.NoError(t, err)
	assert.Equal(t, 1, server.reads)
	commands, _ := r.owned(wsID)
	assert.Equal(t, []string{"cmd-1"}, commands)

	release()
	commands, _ = r.owned(wsID)
	assert.Empty(t, commands)
}

func TestAdmitStartsNothingWhenControlStateCannotBeRead(t *testing.T) {
	server := &fakeControlServer{readErr: errWorkSessionNotFound}
	r := newTestRegistry(server)

	_, err := r.admit(context.Background(), attribution(0), "cmd-1")
	require.ErrorIs(t, err, errWorkSessionStateUnknown)
	commands, _ := r.owned(wsID)
	assert.Empty(t, commands)
}

func TestPauseFencesNewCommandsAndResumeLiftsTheFence(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 1))
	paused := server.lastResult(t)
	assert.Equal(t, "work_session_control_result", paused.Type)
	assert.Equal(t, wsID, paused.WorkSessionID)
	assert.Equal(t, fmt.Sprintf(transition, 1), paused.TransitionID)
	assert.Equal(t, protocol.Uint64String(1), paused.Revision)
	assert.Equal(t, workSessionPaused, paused.State)
	assert.Equal(t, controlResultConfirmed, paused.Result)
	assert.Equal(t, uint32(0), paused.AffectedTrees, "a pause signals no process")
	assert.Equal(t, wsNow.Format(time.RFC3339Nano), paused.ObservedAt)

	_, err := r.admit(context.Background(), attribution(1), "cmd-1")
	require.ErrorIs(t, err, errWorkSessionPaused)
	assert.Equal(t, 0, server.reads, "an applied pause is authoritative; no read is needed to refuse")

	cc.HandleMessage(resumeFrame(t, 2))
	assert.Equal(t, workSessionActive, server.lastResult(t).State)

	release, err := r.admit(context.Background(), attribution(2), "cmd-2")
	require.NoError(t, err)
	release()
}

func TestOnlyTheHighestRevisionApplies(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 3))
	cc.HandleMessage(resumeFrame(t, 2))

	assert.Equal(t, 1, server.resultCount(), "a lower revision is ignored")
	_, err := r.admit(context.Background(), attribution(3), "cmd-1")
	assert.ErrorIs(t, err, errWorkSessionPaused)
}

func TestDuplicateControlPostsTheResultAgain(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 1))
	first := server.lastResult(t)
	cc.HandleMessage(pauseFrame(t, 1))

	require.Equal(t, 2, server.resultCount())
	assert.Equal(t, first, server.lastResult(t))
}

func TestConflictingPayloadForOneRevisionFailsClosed(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 1))
	conflicting := controlFrame(t, "work_session_resume", 1, "active", "human_resume")
	cc.HandleMessage(conflicting)

	result := server.lastResult(t)
	assert.Equal(t, controlResultFailed, result.Result)
	assert.Equal(t, "conflict", result.Error)

	server.readErr = errors.New("unreachable")
	_, err := r.admit(context.Background(), attribution(1), "cmd-1")
	assert.Error(t, err, "a conflict leaves the session unknown until the server is read")
}

func TestCommandAheadOfTheAppliedRevisionReconciles(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 1))
	server.set(workSessionActive, 2) // the resume was not delivered yet

	release, err := r.admit(context.Background(), attribution(2), "cmd-1")
	require.NoError(t, err)
	assert.Equal(t, 1, server.reads)
	release()
}

func TestCommandBehindTheAppliedRevisionIsRefused(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 4)
	r := newTestRegistry(server)

	_, err := r.admit(context.Background(), attribution(3), "cmd-1")
	assert.ErrorIs(t, err, errWorkSessionStale)
}

func TestExpiredSessionIsRefused(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)

	expired := attribution(0)
	expired.ExpiresAt = wsNow
	_, err := r.admit(context.Background(), expired, "cmd-1")
	assert.ErrorIs(t, err, errWorkSessionExpired)
}

func TestTerminalInputFollowsTheFence(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	release, err := r.admit(context.Background(), attribution(0), "cmd-open")
	require.NoError(t, err)
	unregister := r.registerTerminal(wsID, "websh-1", "cmd-open")
	release() // the openpty command finishes; the terminal stays indexed
	_, terminals := r.owned(wsID)
	assert.Equal(t, []string{"cmd-open"}, terminals)
	assert.True(t, r.inputAllowed(wsID))

	cc.HandleMessage(pauseFrame(t, 1))
	assert.False(t, r.inputAllowed(wsID))

	cc.HandleMessage(resumeFrame(t, 2))
	assert.True(t, r.inputAllowed(wsID))

	unregister()
	_, terminals = r.owned(wsID)
	assert.Empty(t, terminals)
}

func TestReconnectFencesUntilTheServerIsRead(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)

	release, err := r.admit(context.Background(), attribution(0), "cmd-open")
	require.NoError(t, err)
	defer release()

	server.readErr = errors.New("unreachable")
	r.reconcileAll(context.Background())
	assert.False(t, r.inputAllowed(wsID), "a failed read leaves the session fenced")

	server.readErr = nil
	server.set(workSessionPaused, 1)
	r.reconcileAll(context.Background())
	assert.False(t, r.inputAllowed(wsID))

	server.set(workSessionActive, 2)
	r.reconcileAll(context.Background())
	assert.True(t, r.inputAllowed(wsID))
}

func TestEndIsTerminalAndReportsItsProcessEffectHonestly(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
	ended := server.lastResult(t)
	assert.Equal(t, workSessionEnded, ended.State)
	assert.Equal(t, controlResultUnsupported, ended.Result, "process termination is not built yet")

	cc.HandleMessage(resumeFrame(t, 3))
	assert.Equal(t, controlResultFailed, server.lastResult(t).Result)
	_, err := r.admit(context.Background(), attribution(3), "cmd-1")
	assert.ErrorIs(t, err, errWorkSessionEnded)
	assert.False(t, r.inputAllowed(wsID))
}

func TestStopProcessesAppliesOnlyToThePausedRevision(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}
	stop := func(revision uint64) []byte {
		frame, err := json.Marshal(map[string]any{"query": "control", "data": map[string]any{
			"type": "work_session_stop_processes", "protocol_version": 1, "client_id": "server-1",
			"work_session_id": wsID, "action_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "revision": fmt.Sprint(revision),
		}})
		require.NoError(t, err)
		return frame
	}

	cc.HandleMessage(stop(1))
	stale := server.lastResult(t)
	assert.Equal(t, controlResultFailed, stale.Result)
	assert.Equal(t, "stale", stale.Error)
	assert.Equal(t, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", stale.ActionID)
	assert.Empty(t, stale.TransitionID)

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stop(1))
	assert.Equal(t, controlResultUnsupported, server.lastResult(t).Result)
}

// contextDispatcher records the context each command ran with.
type contextDispatcher struct {
	ctxs []context.Context
}

func (d *contextDispatcher) Execute(ctx context.Context, _ string, _ *common.CommandArgs) (int, string, error) {
	d.ctxs = append(d.ctxs, ctx)
	return 0, "ok", nil
}

func (d *contextDispatcher) HasHandler(string) bool { return true }

func governedCommand(revision uint64) protocol.Command {
	return protocol.Command{
		Shell:                "system",
		Line:                 "id",
		WorkSessionID:        wsID,
		WorkSessionRevision:  protocol.Uint64String(revision),
		WorkSessionExpiresAt: wsNow.Add(time.Hour).Format(time.RFC3339),
	}
}

func TestCommandRunnerRefusesAPausedSessionsCommand(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	(&ControlClient{workSessions: r}).HandleMessage(pauseFrame(t, 1))
	dispatcher := &contextDispatcher{}
	cr := NewCommandRunner(nil, nil, governedCommand(1), protocol.CommandData{}, dispatcher)
	cr.workSessions = r

	require.NoError(t, cr.Run(context.Background()))
	assert.Empty(t, dispatcher.ctxs, "a paused session's command must never reach execution")
}

func TestCommandRunnerRunsAnActiveSessionsCommandBound(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	dispatcher := &contextDispatcher{}
	cr := NewCommandRunner(nil, nil, governedCommand(0), protocol.CommandData{}, dispatcher)
	cr.workSessions = r

	require.NoError(t, cr.Run(context.Background()))
	require.Len(t, dispatcher.ctxs, 1)
	binding := workSessionFromContext(dispatcher.ctxs[0])
	require.NotNil(t, binding)
	assert.Equal(t, wsID, binding.id)
}

func TestCommandRunnerFailsClosedWithoutARegistry(t *testing.T) {
	dispatcher := &contextDispatcher{}
	cr := NewCommandRunner(nil, nil, governedCommand(0), protocol.CommandData{}, dispatcher)

	require.NoError(t, cr.Run(context.Background()))
	assert.Empty(t, dispatcher.ctxs)
}

func TestCapabilitiesAdvertiseWorkSessionControl(t *testing.T) {
	assert.Contains(t, agentCapabilities(), "work_session_control_v1")
}

func TestControlStateReadUsesAgentAuthAndFailsClosedOnNotFound(t *testing.T) {
	var gotPath, gotAuth string
	status := http.StatusOK
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotPath, gotAuth = req.URL.Path, req.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"work_session_id":"` + wsID + `","state":"paused","revision":"4","expires_at":"2026-11-18T10:00:00Z"}`))
	}))
	defer origin.Close()
	session := &scheduler.Session{BaseURL: origin.URL, Authorization: `id="server-1", key="k"`, Client: origin.Client()}

	snapshot, err := readWorkSessionControlState(context.Background(), session, wsID)
	require.NoError(t, err)
	assert.Equal(t, "/api/work-sessions/sessions/"+wsID+"/control-state/", gotPath)
	assert.Equal(t, `id="server-1", key="k"`, gotAuth)
	assert.Equal(t, WorkSessionSnapshot{State: workSessionPaused, Revision: 4, ExpiresAt: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)}, snapshot)

	status = http.StatusNotFound
	_, err = readWorkSessionControlState(context.Background(), session, wsID)
	assert.ErrorIs(t, err, errWorkSessionNotFound)

	_, err = readWorkSessionControlState(context.Background(), session, "../../servers")
	assert.Error(t, err)
}

func TestControlResultWireShape(t *testing.T) {
	encoded, err := json.Marshal(WorkSessionControlResult{
		Type: "work_session_control_result", WorkSessionID: wsID, TransitionID: "t", Revision: 18446744073709551615,
		State: workSessionPaused, Result: controlResultConfirmed, ObservedAt: "2026-11-18T09:00:00Z", Survivors: []WorkSessionSurvivor{},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"work_session_control_result","work_session_id":"`+wsID+`","transition_id":"t",
		"revision":"18446744073709551615","state":"paused","result":"confirmed","observed_at":"2026-11-18T09:00:00Z",
		"affected_trees":0,"survivors":[]}`, string(encoded))
}

// recordingControl records the process actions it is asked for and answers
// each End with the next queued effect.
type recordingControl struct {
	mu         sync.Mutex
	ends       []OwnedWork
	endEffects []ProcessEffect
	endErr     error
	stopErr    error
}

func (c *recordingControl) Stop(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, c.stopErr
}

func (c *recordingControl) Continue(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, nil
}

func (c *recordingControl) End(_ string, owned OwnedWork) (ProcessEffect, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ends = append(c.ends, owned)
	var effect ProcessEffect
	if len(c.endEffects) > 0 {
		effect, c.endEffects = c.endEffects[0], c.endEffects[1:]
	}
	return effect, c.endErr
}

func (c *recordingControl) endCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ends)
}

func TestReconcileToEndedEndsTheOwnedProcesses(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	control := &recordingControl{endEffects: []ProcessEffect{{AffectedTrees: 1}}}
	r.processes = control
	cc := &ControlClient{workSessions: r}

	release, err := r.admit(context.Background(), attribution(0), "cmd-1")
	require.NoError(t, err)
	defer release()

	// The End was missed while the control socket was down.
	server.set(workSessionEnded, 2)
	r.reconcileAll(context.Background())
	require.Eventually(t, func() bool { return control.endCount() == 1 }, time.Second, 5*time.Millisecond,
		"a session the server reports ended has its processes ended")
	assert.Equal(t, []string{"cmd-1"}, control.ends[0].Commands)

	// The server resends the End until it gets a receipt.
	cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
	ended := server.lastResult(t)
	assert.Equal(t, workSessionEnded, ended.State)
	assert.Equal(t, controlResultConfirmed, ended.Result)
	assert.Empty(t, ended.Error)
	assert.Equal(t, uint32(1), ended.AffectedTrees, "the receipt counts what the reconciled End reached")
}

func TestStaleStopOnAnUntrackedSessionReportsAValidState(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(stopProcessesFrame(t, 1))
	stale := server.lastResult(t)
	assert.Equal(t, controlResultFailed, stale.Result)
	assert.Equal(t, "stale", stale.Error)
	assert.Contains(t, []string{workSessionActive, workSessionPaused, workSessionEnded}, stale.State)
}

func TestProcessActionErrorIsAShortCode(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	long := errors.New(strings.Repeat("operation not permitted; ", 10))
	r.processes = &recordingControl{
		stopErr: errors.Join(long, errProcessSurvivors),
		endErr:  long,
	}
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopProcessesFrame(t, 1))
	stop := server.lastResult(t)
	assert.Equal(t, controlResultFailed, stop.Result)
	assert.Equal(t, "survivors", stop.Error)

	cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
	end := server.lastResult(t)
	assert.Equal(t, controlResultFailed, end.Result)
	assert.Equal(t, "process_control_failed", end.Error)
}

// frameWithoutExpiry is a control frame for a session that has no expiry:
// the server leaves expires_at out.
func frameWithoutExpiry(t *testing.T, kind string, revision uint64, state string) []byte {
	t.Helper()
	frame, err := json.Marshal(map[string]any{"query": "control", "data": map[string]any{
		"type": kind, "protocol_version": 1, "client_id": "server-1", "work_session_id": wsID,
		"transition_id": fmt.Sprintf(transition, revision), "revision": fmt.Sprint(revision),
		"state": state, "reason": "human_end",
	}})
	require.NoError(t, err)
	return frame
}

func TestControlWithoutExpiryApplies(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	control := &recordingControl{}
	r.processes = control
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(frameWithoutExpiry(t, "work_session_pause", 1, workSessionPaused))
	assert.Equal(t, controlResultConfirmed, server.lastResult(t).Result)
	cc.HandleMessage(frameWithoutExpiry(t, "work_session_resume", 2, workSessionActive))
	assert.Equal(t, controlResultConfirmed, server.lastResult(t).Result)
	assert.True(t, r.inputAllowed(wsID), "a session without expiry never expires")

	cc.HandleMessage(frameWithoutExpiry(t, "work_session_end", 3, workSessionEnded))
	assert.Equal(t, controlResultConfirmed, server.lastResult(t).Result)
	assert.Equal(t, 1, control.endCount(), "an End without expiry still ends the processes")
}

func TestEndWithAMalformedExpiryStillEnds(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	control := &recordingControl{}
	r.processes = control
	cc := &ControlClient{workSessions: r}

	frame, err := json.Marshal(map[string]any{"query": "control", "data": map[string]any{
		"type": "work_session_end", "protocol_version": 1, "client_id": "server-1", "work_session_id": wsID,
		"transition_id": fmt.Sprintf(transition, 1), "revision": "1", "state": workSessionEnded, "expires_at": "soon",
	}})
	require.NoError(t, err)
	cc.HandleMessage(frame)
	assert.Equal(t, 1, control.endCount())
	_, err = r.admit(context.Background(), attribution(1), "cmd-1")
	assert.ErrorIs(t, err, errWorkSessionEnded)
}

func TestCommandOfASessionWithoutExpiryIsAdmitted(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	server.state.ExpiresAt = time.Time{}
	r := newTestRegistry(server)
	dispatcher := &contextDispatcher{}
	command := governedCommand(0)
	command.WorkSessionExpiresAt = ""
	cr := NewCommandRunner(nil, nil, command, protocol.CommandData{}, dispatcher)
	cr.workSessions = r

	require.NoError(t, cr.Run(context.Background()))
	assert.Len(t, dispatcher.ctxs, 1)
}

func TestEndedSessionsAreForgottenOnceTornDown(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	r.processes = &recordingControl{}
	cc := &ControlClient{workSessions: r}

	for i := range workSessionEndedLimit + 10 {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i)
		frame, err := json.Marshal(map[string]any{"query": "control", "data": map[string]any{
			"type": "work_session_end", "protocol_version": 1, "client_id": "server-1", "work_session_id": id,
			"transition_id": fmt.Sprintf(transition, 1), "revision": "1", "state": workSessionEnded,
		}})
		require.NoError(t, err)
		cc.HandleMessage(frame)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	assert.LessOrEqual(t, len(r.sessions), workSessionEndedLimit)
}

func TestEndedSessionStaysFencedAfterItIsForgotten(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionEnded, 1)
	r := newTestRegistry(server)
	r.processes = &recordingControl{}

	_, err := r.admit(context.Background(), attribution(1), "cmd-1")
	assert.ErrorIs(t, err, errWorkSessionEnded)
}
