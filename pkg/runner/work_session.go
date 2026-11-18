package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

// capabilityWorkSessionControl says this agent applies Work Session control
// messages and reports their results.
const capabilityWorkSessionControl = "work_session_control_v1"

const (
	workSessionControlStateURL   = "/api/work-sessions/sessions/%s/control-state/"
	workSessionControlResultsURL = "/api/servers/%s/work-session-control-results/"
	workSessionControlStateWait  = 10 * time.Second
)

// Applied states of a Work Session on this host. "ended" covers every
// terminal server state.
const (
	workSessionActive = "active"
	workSessionPaused = "paused"
	workSessionEnded  = "ended"
)

// Control result values.
const (
	controlResultConfirmed   = "confirmed"
	controlResultFailed      = "failed"
	controlResultUnsupported = "unsupported"
)

var (
	errWorkSessionStateUnknown = errors.New("work session control state could not be read")
	errWorkSessionNotFound     = errors.New("work session control state not found")
	errWorkSessionPaused       = errors.New("work session is paused")
	errWorkSessionEnded        = errors.New("work session has ended")
	errWorkSessionExpired      = errors.New("work session has expired")
	errWorkSessionStale        = errors.New("work session revision is stale")
	errWorkSessionNoRegistry   = errors.New("work session control is not available")

	// errProcessControlUnsupported is what a WorkSessionProcessController
	// returns for a process action this host cannot perform.
	errProcessControlUnsupported = errors.New("process control is not supported")
)

// WorkSessionSnapshot is the server's authoritative control state of one
// session, read from the control-state endpoint.
type WorkSessionSnapshot struct {
	State     string                `json:"state"`
	Revision  protocol.Uint64String `json:"revision"`
	ExpiresAt time.Time             `json:"expires_at"`
}

// WorkSessionSurvivor names one owned process that outlived a Stop or End.
type WorkSessionSurvivor struct {
	CommandID string `json:"command_id"`
	PID       int    `json:"pid"`
	PGID      int    `json:"pgid"`
}

// WorkSessionControlResult is the receipt for one control message, posted
// to the server over agent-authenticated HTTP.
type WorkSessionControlResult struct {
	Type          string                `json:"type"`
	WorkSessionID string                `json:"work_session_id"`
	TransitionID  string                `json:"transition_id,omitempty"`
	ActionID      string                `json:"action_id,omitempty"`
	Revision      protocol.Uint64String `json:"revision"`
	State         string                `json:"state"`
	Result        string                `json:"result"`
	ObservedAt    string                `json:"observed_at"`
	AffectedTrees uint32                `json:"affected_trees"`
	Survivors     []WorkSessionSurvivor `json:"survivors"`
	Error         string                `json:"error,omitempty"`
}

// workSessionControl is the data of one Work Session control frame.
type workSessionControl struct {
	Type            string                `json:"type"`
	ProtocolVersion int                   `json:"protocol_version"`
	WorkSessionID   string                `json:"work_session_id"`
	TransitionID    string                `json:"transition_id"`
	ActionID        string                `json:"action_id"`
	Revision        protocol.Uint64String `json:"revision"`
	State           string                `json:"state"`
	ExpiresAt       string                `json:"expires_at"`
	Reason          string                `json:"reason"`
}

// controlTargetState maps a transition message type to the state it sets.
var controlTargetState = map[string]string{
	"work_session_pause":  workSessionPaused,
	"work_session_resume": workSessionActive,
	"work_session_end":    workSessionEnded,
}

const workSessionStopProcesses = "work_session_stop_processes"

// isWorkSessionControl reports whether a control frame type belongs to the
// registry.
func isWorkSessionControl(kind string) bool {
	_, ok := controlTargetState[kind]
	return ok || kind == workSessionStopProcesses
}

// ProcessEffect is what a process action reached.
type ProcessEffect struct {
	AffectedTrees uint32
	Survivors     []WorkSessionSurvivor
}

// WorkSessionProcessController performs the process actions of Work Session
// control on the processes a session owns. Pause never calls it: a pause
// leaves running processes unchanged. A method returns
// errProcessControlUnsupported for an action this host cannot perform.
type WorkSessionProcessController interface {
	// Stop suspends every process group the session owns.
	Stop(id string, owned OwnedWork) (ProcessEffect, error)
	// Continue resumes only the process groups a Stop suspended.
	Continue(id string, owned OwnedWork) (ProcessEffect, error)
	// End terminates every process the session owns.
	End(id string, owned OwnedWork) (ProcessEffect, error)
}

// OwnedWork is the work a session owns on this host, by command ID.
type OwnedWork struct {
	Commands  []string
	Terminals []string
}

// noProcessControl performs no process action. Nothing was stopped, so
// Continue reaches nothing; Stop and End are not supported.
type noProcessControl struct{}

func (noProcessControl) Stop(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, errProcessControlUnsupported
}

func (noProcessControl) Continue(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, nil
}

func (noProcessControl) End(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, errProcessControlUnsupported
}

type trackedWorkSession struct {
	state     string
	revision  uint64
	expiresAt time.Time
	// known is true once the state is authoritative for this connection: read
	// from the server or set by a control message. Unknown state starts nothing.
	known        bool
	transitionID string
	lastResult   *WorkSessionControlResult
	stopResults  map[string]WorkSessionControlResult

	commands  map[string]struct{}
	terminals map[string]string // terminal session ID -> opening command ID
}

func (s *trackedWorkSession) owned() OwnedWork {
	work := OwnedWork{Commands: []string{}, Terminals: []string{}}
	for id := range s.commands {
		work.Commands = append(work.Commands, id)
	}
	for _, commandID := range s.terminals {
		work.Terminals = append(work.Terminals, commandID)
	}
	slices.Sort(work.Commands)
	slices.Sort(work.Terminals)
	return work
}

func (s *trackedWorkSession) idle() bool {
	return len(s.commands) == 0 && len(s.terminals) == 0
}

// WorkSessionRegistry indexes commands and terminals by Work Session and
// holds each session's applied control state. Admission, registration and
// the fence check share one lock, so a pause applied under it lets no new
// work register afterwards.
type WorkSessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*trackedWorkSession

	readState  func(ctx context.Context, id string) (WorkSessionSnapshot, error)
	postResult func(result WorkSessionControlResult)
	processes  WorkSessionProcessController
	now        func() time.Time
}

func newWorkSessionRegistry(
	readState func(ctx context.Context, id string) (WorkSessionSnapshot, error),
	postResult func(result WorkSessionControlResult),
) *WorkSessionRegistry {
	return &WorkSessionRegistry{
		sessions:   map[string]*trackedWorkSession{},
		readState:  readState,
		postResult: postResult,
		processes:  noProcessControl{},
		now:        time.Now,
	}
}

// NewWorkSessionRegistry builds the registry that reads control state with
// session and posts results through the request queue.
func NewWorkSessionRegistry(session *scheduler.Session, serverID string) *WorkSessionRegistry {
	return newWorkSessionRegistry(
		func(ctx context.Context, id string) (WorkSessionSnapshot, error) {
			return readWorkSessionControlState(ctx, session, id)
		},
		func(result WorkSessionControlResult) {
			scheduler.Rqueue.Post(fmt.Sprintf(workSessionControlResultsURL, serverID), result, 10, time.Time{})
		},
	)
}

func readWorkSessionControlState(_ context.Context, session *scheduler.Session, id string) (WorkSessionSnapshot, error) {
	if session == nil {
		return WorkSessionSnapshot{}, errWorkSessionStateUnknown
	}
	if err := protocol.ValidateWorkSessionID(id); err != nil {
		return WorkSessionSnapshot{}, err
	}
	body, status, err := session.Get(fmt.Sprintf(workSessionControlStateURL, id), workSessionControlStateWait)
	if err != nil {
		return WorkSessionSnapshot{}, err
	}
	if status == http.StatusNotFound {
		return WorkSessionSnapshot{}, errWorkSessionNotFound
	}
	if status != http.StatusOK {
		return WorkSessionSnapshot{}, fmt.Errorf("control state read returned %d", status)
	}
	var snapshot WorkSessionSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return WorkSessionSnapshot{}, err
	}
	switch snapshot.State {
	case workSessionActive, workSessionPaused, workSessionEnded:
	default:
		return WorkSessionSnapshot{}, fmt.Errorf("unknown work session state %q", snapshot.State)
	}
	return snapshot, nil
}

func (r *WorkSessionRegistry) session(id string) *trackedWorkSession {
	s, ok := r.sessions[id]
	if !ok {
		s = &trackedWorkSession{
			state:       workSessionActive,
			stopResults: map[string]WorkSessionControlResult{},
			commands:    map[string]struct{}{},
			terminals:   map[string]string{},
		}
		r.sessions[id] = s
	}
	return s
}

// forget drops an idle active session, whose state the server can give
// again. A paused or ended one stays, so its fence outlives its work.
func (r *WorkSessionRegistry) forget(id string, s *trackedWorkSession) {
	if s.idle() && s.state == workSessionActive {
		delete(r.sessions, id)
	}
}

// admit registers commandID under its Work Session when the session's
// applied state lets new work start, reading the server's control state
// first when the local state is unknown or behind the command's revision.
// The returned release unregisters the command.
func (r *WorkSessionRegistry) admit(ctx context.Context, ws protocol.WorkSession, commandID string) (func(), error) {
	reconciled := false
	for {
		r.mu.Lock()
		s := r.session(ws.ID)
		err := r.admissible(s, ws)
		if err == nil {
			s.commands[commandID] = struct{}{}
			r.mu.Unlock()
			return func() { r.releaseCommand(ws.ID, commandID) }, nil
		}
		needsRead := errors.Is(err, errWorkSessionStateUnknown)
		if !needsRead || reconciled {
			r.forget(ws.ID, s)
			r.mu.Unlock()
			return nil, err
		}
		r.mu.Unlock()

		reconciled = true
		if err := r.reconcile(ctx, ws.ID); err != nil {
			log.Warn().Err(err).Str("work_session_id", ws.ID).Msg("Could not read work session control state; starting nothing for it.")
			r.mu.Lock()
			if s, ok := r.sessions[ws.ID]; ok {
				r.forget(ws.ID, s)
			}
			r.mu.Unlock()
			return nil, errWorkSessionStateUnknown
		}
	}
}

// admissible decides under r.mu whether new work at ws may start.
func (r *WorkSessionRegistry) admissible(s *trackedWorkSession, ws protocol.WorkSession) error {
	switch {
	case s.state == workSessionEnded:
		return errWorkSessionEnded
	case !s.known || ws.Revision > s.revision:
		return errWorkSessionStateUnknown
	case ws.Revision < s.revision:
		return errWorkSessionStale
	case s.state != workSessionActive:
		return errWorkSessionPaused
	case !r.now().Before(ws.ExpiresAt), !s.expiresAt.IsZero() && !r.now().Before(s.expiresAt):
		return errWorkSessionExpired
	}
	return nil
}

func (r *WorkSessionRegistry) releaseCommand(id, commandID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[id]; ok {
		delete(s.commands, commandID)
		r.forget(id, s)
	}
}

// registerTerminal indexes an open terminal under its Work Session until
// the returned function is called.
func (r *WorkSessionRegistry) registerTerminal(id, terminalID, commandID string) func() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session(id).terminals[terminalID] = commandID
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if s, ok := r.sessions[id]; ok {
			delete(s.terminals, terminalID)
			r.forget(id, s)
		}
	}
}

// inputAllowed reports whether terminal input of the session may reach its
// PTY. Input is dropped, never buffered, while it is not.
func (r *WorkSessionRegistry) inputAllowed(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok || !s.known || s.state != workSessionActive {
		return false
	}
	return s.expiresAt.IsZero() || r.now().Before(s.expiresAt)
}

// owned lists the command IDs of the session's commands and of the commands
// that opened its terminals.
func (r *WorkSessionRegistry) owned(id string) (commands, terminals []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, nil
	}
	work := s.owned()
	return work.Commands, work.Terminals
}

// reconcile reads the server's control state of one session and applies it.
func (r *WorkSessionRegistry) reconcile(ctx context.Context, id string) error {
	snapshot, err := r.readState(ctx, id)
	if err != nil {
		return err
	}
	revision := uint64(snapshot.Revision)

	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.session(id)
	switch {
	case s.state == workSessionEnded:
		// A terminal fence is never lifted.
	case revision < s.revision:
		// A control message applied a newer revision while the read was in flight.
		if !s.known {
			return errWorkSessionStale
		}
	default:
		if revision != s.revision {
			s.transitionID = ""
			s.lastResult = nil
		}
		s.state, s.revision, s.expiresAt, s.known = snapshot.State, revision, snapshot.ExpiresAt, true
	}
	return nil
}

// reconcileAll marks every tracked session unknown, which fences it, and
// reads each one's control state again. Call it on every reconnect of the
// control socket, which may have missed control messages.
func (r *WorkSessionRegistry) reconcileAll(ctx context.Context) {
	r.mu.Lock()
	ids := make([]string, 0, len(r.sessions))
	for id, s := range r.sessions {
		s.known = false
		ids = append(ids, id)
	}
	r.mu.Unlock()

	for _, id := range ids {
		if err := r.reconcile(ctx, id); err != nil {
			log.Warn().Err(err).Str("work_session_id", id).Msg("Could not read work session control state after reconnect; the session stays fenced.")
		}
	}
}

// handleControl applies one Work Session control frame and posts its result.
func (r *WorkSessionRegistry) handleControl(raw json.RawMessage) {
	var msg workSessionControl
	if err := json.Unmarshal(raw, &msg); err != nil {
		log.Warn().Err(err).Msg("Invalid work session control message")
		return
	}
	if err := protocol.ValidateWorkSessionID(msg.WorkSessionID); err != nil {
		log.Warn().Err(err).Str("type", msg.Type).Msg("Invalid work session control message")
		return
	}
	if msg.Type == workSessionStopProcesses {
		r.handleStop(msg)
		return
	}
	if result, ok := r.applyTransition(msg); ok {
		r.postResult(result)
	}
}

func (r *WorkSessionRegistry) newResult(msg workSessionControl, state, result string) WorkSessionControlResult {
	return WorkSessionControlResult{
		Type:          "work_session_control_result",
		WorkSessionID: msg.WorkSessionID,
		TransitionID:  msg.TransitionID,
		ActionID:      msg.ActionID,
		Revision:      msg.Revision,
		State:         state,
		Result:        result,
		ObservedAt:    r.now().UTC().Format(time.RFC3339Nano),
		Survivors:     []WorkSessionSurvivor{},
	}
}

// applyTransition applies a pause, resume or end under r.mu and returns the
// result to post, or false when the message is ignored.
func (r *WorkSessionRegistry) applyTransition(msg workSessionControl) (WorkSessionControlResult, bool) {
	target := controlTargetState[msg.Type]
	revision := uint64(msg.Revision)

	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.session(msg.WorkSessionID)

	if msg.ProtocolVersion != 1 || msg.TransitionID == "" || msg.State != target {
		result := r.newResult(msg, s.state, controlResultUnsupported)
		result.Error = "invalid_message"
		r.forget(msg.WorkSessionID, s)
		return result, true
	}

	switch {
	case revision < s.revision:
		log.Debug().Str("work_session_id", msg.WorkSessionID).Uint64("revision", revision).Msg("Ignored a work session control older than the applied revision")
		r.forget(msg.WorkSessionID, s)
		return WorkSessionControlResult{}, false
	case revision == s.revision && s.transitionID == msg.TransitionID && s.state == target && s.lastResult != nil:
		return *s.lastResult, true
	case revision == s.revision && s.known && (s.state != target || s.transitionID != "" && s.transitionID != msg.TransitionID):
		// One revision with two payloads: apply neither, and read the server
		// before starting anything more.
		s.known = false
		result := r.newResult(msg, s.state, controlResultFailed)
		result.Error = "conflict"
		return result, true
	case s.state == workSessionEnded:
		result := r.newResult(msg, s.state, controlResultFailed)
		result.Error = "ended"
		return result, true
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, msg.ExpiresAt)
	if err != nil {
		result := r.newResult(msg, s.state, controlResultFailed)
		result.Error = "invalid_message"
		return result, true
	}
	s.state, s.revision, s.expiresAt, s.known, s.transitionID = target, revision, expiresAt, true, msg.TransitionID

	var effect ProcessEffect
	switch target {
	case workSessionActive:
		effect, err = r.processes.Continue(msg.WorkSessionID, s.owned())
	case workSessionEnded:
		effect, err = r.processes.End(msg.WorkSessionID, s.owned())
	}
	result := r.newResult(msg, target, processResult(err))
	result.AffectedTrees = effect.AffectedTrees
	if effect.Survivors != nil {
		result.Survivors = effect.Survivors
	}
	if err != nil && !errors.Is(err, errProcessControlUnsupported) {
		result.Error = err.Error()
	}
	s.lastResult = &result
	return result, true
}

// handleStop applies a person's Stop to a session paused at its revision.
func (r *WorkSessionRegistry) handleStop(msg workSessionControl) {
	r.mu.Lock()
	result, ok := r.applyStop(msg)
	r.mu.Unlock()
	if ok {
		r.postResult(result)
	}
}

func (r *WorkSessionRegistry) applyStop(msg workSessionControl) (WorkSessionControlResult, bool) {
	msg.TransitionID = ""
	if msg.ActionID == "" {
		return WorkSessionControlResult{}, false
	}
	s, ok := r.sessions[msg.WorkSessionID]
	if ok {
		if previous, seen := s.stopResults[msg.ActionID]; seen {
			return previous, true
		}
	}
	if !ok || !s.known || s.state != workSessionPaused || s.revision != uint64(msg.Revision) {
		state := ""
		if ok {
			state = s.state
		}
		result := r.newResult(msg, state, controlResultFailed)
		result.Error = "stale"
		return result, true
	}

	effect, err := r.processes.Stop(msg.WorkSessionID, s.owned())
	result := r.newResult(msg, s.state, processResult(err))
	result.AffectedTrees = effect.AffectedTrees
	if effect.Survivors != nil {
		result.Survivors = effect.Survivors
	}
	if err != nil && !errors.Is(err, errProcessControlUnsupported) {
		result.Error = err.Error()
	}
	s.stopResults[msg.ActionID] = result
	return result, true
}

func processResult(err error) string {
	switch {
	case err == nil:
		return controlResultConfirmed
	case errors.Is(err, errProcessControlUnsupported):
		return controlResultUnsupported
	default:
		return controlResultFailed
	}
}

// workSessionBinding ties work running in a context to its Work Session.
type workSessionBinding struct {
	registry *WorkSessionRegistry
	id       string
}

type workSessionKey struct{}

func withWorkSession(ctx context.Context, binding *workSessionBinding) context.Context {
	return context.WithValue(ctx, workSessionKey{}, binding)
}

// workSessionFromContext returns the Work Session the context's command was
// admitted under, or nil for session-less work.
func workSessionFromContext(ctx context.Context) *workSessionBinding {
	binding, _ := ctx.Value(workSessionKey{}).(*workSessionBinding)
	return binding
}

// inputAllowed is nil-safe: session-less terminals always take input.
func (b *workSessionBinding) inputAllowed() bool {
	return b == nil || b.registry.inputAllowed(b.id)
}

// registerTerminal is nil-safe and returns a no-op for session-less terminals.
func (b *workSessionBinding) registerTerminal(terminalID, commandID string) func() {
	if b == nil {
		return func() {}
	}
	return b.registry.registerTerminal(b.id, terminalID, commandID)
}
