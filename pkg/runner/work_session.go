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
	"unicode/utf8"

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

	workSessionProcessInventoryURL = "/api/servers/%s/work-session-process-inventory/"
	// workSessionInventoryInterval is how often a paused session's processes
	// are reported again.
	workSessionInventoryInterval = 30 * time.Second
	// workSessionInventoryLimit caps the entries of one report.
	workSessionInventoryLimit = 100
	// workSessionArgsLimit caps the argument bytes of one entry.
	workSessionArgsLimit = 1024
	// workSessionEndedLimit caps the ended sessions kept to answer a resent
	// End with its receipt. An older one is read from the server again.
	workSessionEndedLimit = 256
)

// Kinds of owned work.
const (
	ownedKindCommand  = "command"
	ownedKindTerminal = "terminal"
)

// Process states in an inventory entry.
const (
	processRunning = "running"
	processStopped = "stopped"
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

// Error codes of a process action's result.
const (
	errorCodeSurvivors      = "survivors"
	errorCodeProcessControl = "process_control_failed"
)

var (
	errWorkSessionStateUnknown = errors.New("work session control state could not be read")
	errWorkSessionNotFound     = errors.New("work session control state not found")
	errWorkSessionPaused       = errors.New("work session is paused")
	errWorkSessionEnded        = errors.New("work session has ended")
	errWorkSessionExpired      = errors.New("work session has expired")
	errWorkSessionStale        = errors.New("work session revision is stale")
	errWorkSessionNoRegistry   = errors.New("work session control is not available")
	errWorkSessionAttribution  = errors.New("invalid work session attribution")

	// errProcessControlUnsupported is what a WorkSessionProcessController
	// returns for a process action this host cannot perform.
	errProcessControlUnsupported = errors.New("process control is not supported")
	// errProcessSurvivors is what a process action returns when an owned
	// process did not reach the requested effect.
	errProcessSurvivors = errors.New("survivors")
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
	// Sessions are the process sessions the session's commands and terminals
	// started, kept after a command finishes while its children live on.
	Sessions []OwnedSession
}

// OwnedSession is one process session a command or terminal started: its
// leader has PID SID. StartedAt is the leader's start time in Unix
// milliseconds, which tells a reused SID apart.
type OwnedSession struct {
	Kind      string
	CommandID string
	SID       int
	StartedAt int64
}

// WorkSessionProcess is one entry of a process inventory.
type WorkSessionProcess struct {
	Kind      string   `json:"kind"`
	CommandID string   `json:"command_id"`
	PID       int      `json:"pid"`
	PGID      int      `json:"pgid"`
	StartedAt string   `json:"started_at"`
	State     string   `json:"state"`
	Args      []string `json:"args"`
}

// WorkSessionProcessInventory reports the processes one paused session owns
// on this host.
type WorkSessionProcessInventory struct {
	WorkSessionID string                `json:"work_session_id"`
	Revision      protocol.Uint64String `json:"revision"`
	ObservedAt    string                `json:"observed_at"`
	Truncated     bool                  `json:"truncated"`
	Processes     []WorkSessionProcess  `json:"processes"`
}

// processInventory is implemented by a WorkSessionProcessController that can
// list the processes a session owns.
type processInventory interface {
	Inventory(owned OwnedWork) ([]WorkSessionProcess, error)
}

// cutArgs keeps the leading arguments whose bytes fit limit, cutting the
// last one at a UTF-8 boundary.
func cutArgs(args []string, limit int) []string {
	cut := []string{}
	for _, arg := range args {
		if len(arg) > limit {
			end := limit
			for end > 0 && !utf8.RuneStart(arg[end]) {
				end--
			}
			if end > 0 {
				cut = append(cut, arg[:end])
			}
			break
		}
		cut = append(cut, arg)
		limit -= len(arg)
	}
	return cut
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

// cancelProcessControl serves a host that cannot suspend a process group.
// Stop is unsupported. End applies the existing command cancel to every
// owned command and terminal, which on Windows terminates its job object,
// and reports unsupported: it does not observe the whole tree end.
type cancelProcessControl struct {
	cancel func(commandID string)
}

func (cancelProcessControl) Stop(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, errProcessControlUnsupported
}

func (cancelProcessControl) Continue(string, OwnedWork) (ProcessEffect, error) {
	return ProcessEffect{}, nil
}

func (c cancelProcessControl) End(_ string, owned OwnedWork) (ProcessEffect, error) {
	commands := slices.Concat(owned.Commands, owned.Terminals)
	if c.cancel != nil {
		for _, commandID := range commands {
			c.cancel(commandID)
		}
	}
	return ProcessEffect{AffectedTrees: uint32(len(commands))}, errProcessControlUnsupported
}

type trackedWorkSession struct {
	state     string
	revision  uint64
	expiresAt time.Time
	// known is true once the state is authoritative for this connection: read
	// from the server or set by a control message. Unknown state starts nothing.
	known        bool
	hasState     bool
	conflicted   bool
	transitionID string
	lastResult   *WorkSessionControlResult
	stopResults  map[string]WorkSessionControlResult

	commands  map[string]struct{}
	terminals map[string]string // terminal session ID -> opening command ID
	processes map[int]OwnedSession

	// stopInventory ends the periodic inventory while the session is paused.
	stopInventory chan struct{}

	// ending is set while an End found by reconciliation is still to run.
	ending bool
	// reconciledEnd is what that End reached, until an End receipt counts it.
	reconciledEnd *ProcessEffect
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
	for _, process := range s.processes {
		work.Sessions = append(work.Sessions, process)
	}
	slices.SortFunc(work.Sessions, func(a, b OwnedSession) int { return a.SID - b.SID })
	return work
}

func (s *trackedWorkSession) idle() bool {
	return len(s.commands) == 0 && len(s.terminals) == 0 && len(s.processes) == 0
}

// WorkSessionRegistry indexes commands and terminals by Work Session and
// holds each session's applied control state. Admission, registration and
// the fence check share one lock, so a pause applied under it lets no new
// work register afterwards.
type WorkSessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*trackedWorkSession
	// ended lists the tracked ended sessions, oldest first.
	ended []string

	// actions serializes control, reconciliation and release/adoption.
	// Process actions leave r.mu free for admission to check the session fence.
	actions sync.Mutex
	// reports serializes inventory reports.
	reports sync.Mutex

	readState     func(ctx context.Context, id string) (WorkSessionSnapshot, error)
	postResult    func(result WorkSessionControlResult)
	postInventory func(inventory WorkSessionProcessInventory)
	processes     WorkSessionProcessController
	// sessionAlive reports whether an owned process session still has a
	// live member.
	sessionAlive func(OwnedSession) bool
	now          func() time.Time
	// inventoryInterval is how often a paused session is reported again.
	inventoryInterval time.Duration
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
		sessionAlive: func(OwnedSession) bool {
			return false
		},
		now:               time.Now,
		inventoryInterval: workSessionInventoryInterval,
	}
}

// NewWorkSessionRegistry builds the registry that reads control state with
// session and posts results and inventories through the request queue.
// cancelCommand is the existing command cancel, which End applies to every
// owned command and terminal.
func NewWorkSessionRegistry(session *scheduler.Session, serverID string, cancelCommand func(id string)) *WorkSessionRegistry {
	r := newWorkSessionRegistry(
		func(ctx context.Context, id string) (WorkSessionSnapshot, error) {
			return readWorkSessionControlState(ctx, session, id)
		},
		func(result WorkSessionControlResult) {
			scheduler.Rqueue.Post(fmt.Sprintf(workSessionControlResultsURL, serverID), result, 10, time.Time{})
		},
	)
	r.processes = newProcessControl(cancelCommand)
	r.sessionAlive = ownedSessionAlive
	r.postInventory = func(inventory WorkSessionProcessInventory) {
		scheduler.Rqueue.Post(fmt.Sprintf(workSessionProcessInventoryURL, serverID), inventory, 10, time.Time{})
	}
	return r
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
			processes:   map[int]OwnedSession{},
		}
		r.sessions[id] = s
	}
	return s
}

// forget drops an idle active session, whose state the server can give
// again. A paused one stays, so its fence and inventory outlive its work. An
// ended one stays to answer a resent End until workSessionEndedLimit newer
// ones push it out; dropped, it is fenced again by reading the server.
func (r *WorkSessionRegistry) forget(id string, s *trackedWorkSession) {
	if s.idle() && s.state == workSessionActive {
		delete(r.sessions, id)
	}
	r.trimEnded()
}

// markEnded records that the session just reached ended. Call it under r.mu.
func (r *WorkSessionRegistry) markEnded(id string) {
	r.ended = append(r.ended, id)
	r.trimEnded()
}

// trimEnded drops the oldest ended sessions whose processes are torn down
// while more than workSessionEndedLimit are kept. Call it under r.mu.
func (r *WorkSessionRegistry) trimEnded() {
	excess := len(r.ended) - workSessionEndedLimit
	if excess <= 0 {
		return
	}
	kept := r.ended[:0]
	for _, id := range r.ended {
		s, ok := r.sessions[id]
		switch {
		case !ok || s.state != workSessionEnded:
			continue
		case excess > 0 && s.idle() && !s.ending:
			delete(r.sessions, id)
			excess--
			continue
		}
		kept = append(kept, id)
	}
	clear(r.ended[len(kept):])
	r.ended = kept
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
	case !ws.ExpiresAt.IsZero() && !r.now().Before(ws.ExpiresAt), !s.expiresAt.IsZero() && !r.now().Before(s.expiresAt):
		return errWorkSessionExpired
	}
	return nil
}

func (r *WorkSessionRegistry) releaseCommand(id, commandID string) {
	r.actions.Lock()
	defer r.actions.Unlock()
	r.mu.Lock()
	if s, ok := r.sessions[id]; ok {
		delete(s.commands, commandID)
	}
	r.mu.Unlock()
	r.adoptProcesses(id, ownedKindCommand, commandID)
	r.releaseIdle(id)
}

// releaseIdle drops the process sessions finished work left empty, then
// forgets the session when nothing of it remains.
func (r *WorkSessionRegistry) releaseIdle(id string) {
	r.pruneProcesses(id)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[id]; ok {
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
		r.actions.Lock()
		defer r.actions.Unlock()
		r.mu.Lock()
		if s, ok := r.sessions[id]; ok {
			delete(s.terminals, terminalID)
		}
		r.mu.Unlock()
		r.adoptProcesses(id, ownedKindTerminal, commandID)
		r.releaseIdle(id)
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
	r.actions.Lock()
	defer r.actions.Unlock()
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
		if snapshot.State == workSessionEnded && revision >= s.revision {
			s.known, s.conflicted = true, false
		}
	case revision < s.revision:
		// A control message applied a newer revision while the read was in flight.
		if !s.known {
			return errWorkSessionStale
		}
	default:
		if revision != s.revision || snapshot.State != s.state {
			s.transitionID = ""
			s.lastResult = nil
		}
		resumed := s.state == workSessionPaused && snapshot.State == workSessionActive
		s.state, s.revision, s.expiresAt, s.known = snapshot.State, revision, snapshot.ExpiresAt, true
		s.hasState = true
		s.conflicted = false
		r.syncInventoryLoop(id, s)
		if resumed {
			// The Resume may have been missed; continue what a Stop suspended
			// now, as the Resume would have.
			go r.continueReconciled(id, s, revision)
		}
		if s.state == workSessionEnded {
			r.markEnded(id)
			// The End may have been missed; end the processes now rather
			// than when it is resent.
			s.ending = true
			go r.endReconciled(id, s)
		}
	}
	return nil
}

// continueReconciled continues the process groups a Stop suspended in a
// session reconciliation found active after paused, unless a newer control
// changed the session first.
func (r *WorkSessionRegistry) continueReconciled(id string, s *trackedWorkSession, revision uint64) {
	r.actions.Lock()
	defer r.actions.Unlock()
	r.mu.Lock()
	current := s.state == workSessionActive && s.revision == revision
	r.mu.Unlock()
	if !current {
		return
	}
	r.pruneProcesses(id)
	r.mu.Lock()
	owned := s.owned()
	r.mu.Unlock()
	if _, err := r.processes.Continue(id, owned); err != nil {
		log.Warn().Err(err).Str("work_session_id", id).Msg("Could not continue every stopped process of a resumed work session.")
	}
	r.reportInventory(id, false)
}

// endReconciled ends the processes of a session reconciliation found ended,
// unless an End message ended them first.
func (r *WorkSessionRegistry) endReconciled(id string, s *trackedWorkSession) {
	r.actions.Lock()
	defer r.actions.Unlock()
	r.mu.Lock()
	done := s.lastResult != nil
	r.mu.Unlock()
	var effect ProcessEffect
	var err error
	if !done {
		effect, err = r.endProcesses(id, s)
		if err != nil && !errors.Is(err, errProcessControlUnsupported) {
			log.Warn().Err(err).Str("work_session_id", id).Msg("Could not end every process of an ended work session.")
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s.ending = false
	if !done {
		s.reconciledEnd = &effect
	}
	r.forget(id, s)
}

// endProcesses runs End on every process the session owns. A process
// session that still has a live member afterwards stays tracked, so a resent
// End retries the survivors this one reported. Call it without r.mu.
func (r *WorkSessionRegistry) endProcesses(id string, s *trackedWorkSession) (ProcessEffect, error) {
	r.pruneProcesses(id)
	r.mu.Lock()
	owned := s.owned()
	r.mu.Unlock()
	effect, err := r.processes.End(id, owned)
	r.pruneProcesses(id)
	return effect, err
}

// reconcileAll marks every tracked session unknown, which fences it, and
// reads each one's control state again. Call it on every reconnect of the
// control socket, which may have missed control messages.
func (r *WorkSessionRegistry) reconcileAll(ctx context.Context) {
	r.actions.Lock()
	r.mu.Lock()
	ids := make([]string, 0, len(r.sessions))
	for id, s := range r.sessions {
		s.known = false
		ids = append(ids, id)
	}
	r.mu.Unlock()
	r.actions.Unlock()

	for _, id := range ids {
		if err := r.reconcile(ctx, id); err != nil {
			log.Warn().Err(err).Str("work_session_id", id).Msg("Could not read work session control state after reconnect; the session stays fenced.")
			continue
		}
		r.reportInventory(id, true)
	}
}

// handleControl applies one Work Session control frame and posts its result.
// Control frames are handled one at a time.
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
	r.actions.Lock()
	defer r.actions.Unlock()
	if msg.Type == workSessionStopProcesses {
		r.handleStop(msg)
		return
	}
	result, ok := r.applyTransition(msg)
	if !ok {
		return
	}
	r.postResult(result)
	// A paused session is reported until it resumes; a resume reports once
	// more so the console stops showing processes as stopped.
	if result.TransitionID != "" && result.Error == "" && (result.State == workSessionPaused || result.State == workSessionActive) {
		r.reportInventory(msg.WorkSessionID, false)
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

// applyTransition applies a pause, resume or end and returns the result to
// post, or false when the message is ignored. The state changes under r.mu;
// the process action runs after r.mu is released.
func (r *WorkSessionRegistry) applyTransition(msg workSessionControl) (WorkSessionControlResult, bool) {
	target := controlTargetState[msg.Type]

	r.mu.Lock()
	s := r.session(msg.WorkSessionID)
	if result, ok, done := r.decideTransition(msg, s, target); done {
		r.mu.Unlock()
		return result, ok
	}
	r.mu.Unlock()

	var effect ProcessEffect
	var err error
	switch target {
	case workSessionActive:
		r.pruneProcesses(msg.WorkSessionID)
		r.mu.Lock()
		owned := s.owned()
		r.mu.Unlock()
		effect, err = r.processes.Continue(msg.WorkSessionID, owned)
	case workSessionEnded:
		effect, err = r.endProcesses(msg.WorkSessionID, s)
	}
	result := r.newResult(msg, target, processResult(err))
	result.AffectedTrees = effect.AffectedTrees
	if effect.Survivors != nil {
		result.Survivors = effect.Survivors
	}
	result.Error = processErrorCode(msg, err)

	r.mu.Lock()
	if target == workSessionEnded && s.reconciledEnd != nil {
		// The processes were ended when reconciliation found the session
		// ended; this End reached only what was left.
		result.AffectedTrees += s.reconciledEnd.AffectedTrees
		s.reconciledEnd = nil
	}
	s.lastResult = &result
	if target == workSessionEnded {
		r.forget(msg.WorkSessionID, s)
	}
	r.mu.Unlock()
	return result, true
}

// processErrorCode is the short error code of a process action's result.
// The detail goes to the log: the result's error is a code, not a message.
func processErrorCode(msg workSessionControl, err error) string {
	if err == nil || errors.Is(err, errProcessControlUnsupported) {
		return ""
	}
	log.Warn().Err(err).Str("work_session_id", msg.WorkSessionID).Str("type", msg.Type).Msg("A work session process action did not reach its full effect.")
	if errors.Is(err, errProcessSurvivors) {
		return errorCodeSurvivors
	}
	return errorCodeProcessControl
}

// decideTransition checks msg against the applied state under r.mu. It
// returns done with the result to post, or applies the target state and
// returns not done when the process action is still to run.
func (r *WorkSessionRegistry) decideTransition(msg workSessionControl, s *trackedWorkSession, target string) (WorkSessionControlResult, bool, bool) {
	revision := uint64(msg.Revision)
	if msg.ProtocolVersion != 1 || msg.TransitionID == "" || msg.State != target {
		result := r.newResult(msg, s.state, controlResultUnsupported)
		result.Error = "invalid_message"
		r.forget(msg.WorkSessionID, s)
		return result, true, true
	}
	end := target == workSessionEnded

	switch {
	case revision < s.revision && !end:
		log.Debug().Str("work_session_id", msg.WorkSessionID).Uint64("revision", revision).Msg("Ignored a work session control older than the applied revision")
		r.forget(msg.WorkSessionID, s)
		return WorkSessionControlResult{}, false, true
	case revision == s.revision && s.transitionID == msg.TransitionID && s.state == target && s.lastResult != nil &&
		!(end && len(s.lastResult.Survivors) > 0 && len(s.processes) > 0):
		// A resent End whose receipt reported survivors still tracked runs
		// again to reach them.
		return *s.lastResult, true, true
	case revision == s.revision && (s.conflicted || (s.known || s.hasState) && (s.state != target || s.transitionID != "" && s.transitionID != msg.TransitionID)):
		// One revision with two payloads: apply neither, and read the server
		// before starting anything more.
		s.known = false
		s.conflicted = true
		result := r.newResult(msg, s.state, controlResultFailed)
		result.Error = "conflict"
		return result, true, true
	case s.state == workSessionEnded && !end:
		result := r.newResult(msg, s.state, controlResultFailed)
		result.Error = "ended"
		return result, true, true
	}

	// A session without an expiry carries none. An End is applied whatever
	// its expiry says, and so is a Pause, which only fences.
	expiresAt := s.expiresAt
	if msg.ExpiresAt == "" {
		expiresAt = time.Time{}
	} else if parsed, err := time.Parse(time.RFC3339Nano, msg.ExpiresAt); err == nil {
		expiresAt = parsed
	} else if target == workSessionActive {
		result := r.newResult(msg, s.state, controlResultFailed)
		result.Error = "invalid_message"
		return result, true, true
	}
	newlyEnded := end && s.state != workSessionEnded
	s.state, s.revision, s.expiresAt, s.known, s.transitionID = target, max(s.revision, revision), expiresAt, true, msg.TransitionID
	s.hasState = true
	s.conflicted = false
	if newlyEnded {
		r.markEnded(msg.WorkSessionID)
	}
	s.lastResult = nil
	r.syncInventoryLoop(msg.WorkSessionID, s)
	return WorkSessionControlResult{}, false, false
}

// handleStop applies a person's Stop to a session paused at its revision
// and reports the inventory it left.
func (r *WorkSessionRegistry) handleStop(msg workSessionControl) {
	msg.TransitionID = ""
	if msg.ActionID == "" {
		return
	}
	r.mu.Lock()
	result, done := r.decideStop(msg)
	r.mu.Unlock()
	if done {
		r.postResult(result)
		return
	}

	r.pruneProcesses(msg.WorkSessionID)
	r.mu.Lock()
	s := r.session(msg.WorkSessionID)
	owned, state := s.owned(), s.state
	r.mu.Unlock()

	effect, err := r.processes.Stop(msg.WorkSessionID, owned)
	result = r.newResult(msg, state, processResult(err))
	result.AffectedTrees = effect.AffectedTrees
	if effect.Survivors != nil {
		result.Survivors = effect.Survivors
	}
	result.Error = processErrorCode(msg, err)

	r.mu.Lock()
	s.stopResults[msg.ActionID] = result
	r.mu.Unlock()
	r.postResult(result)
	r.reportInventory(msg.WorkSessionID, true)
}

// decideStop returns done with the result to post when the Stop is a
// duplicate or stale, under r.mu.
func (r *WorkSessionRegistry) decideStop(msg workSessionControl) (WorkSessionControlResult, bool) {
	s, ok := r.sessions[msg.WorkSessionID]
	state := workSessionActive
	if ok {
		state = s.state
	}
	if msg.ProtocolVersion != 1 {
		result := r.newResult(msg, state, controlResultUnsupported)
		result.Error = "invalid_message"
		return result, true
	}
	if ok {
		if previous, seen := s.stopResults[msg.ActionID]; seen {
			return previous, true
		}
	}
	if !ok || !s.known || s.state != workSessionPaused || s.revision != uint64(msg.Revision) {
		// An untracked session has applied no control: it reports the
		// state a session starts in.
		result := r.newResult(msg, state, controlResultFailed)
		result.Error = "stale"
		return result, true
	}
	return WorkSessionControlResult{}, false
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

// trackProcess records a process session a command or terminal of the
// session started, so its children stay owned after the command finishes.
func (r *WorkSessionRegistry) trackProcess(id, kind, commandID string, pid int) {
	if pid <= 1 {
		return
	}
	session := OwnedSession{Kind: kind, CommandID: commandID, SID: pid, StartedAt: processStartedAt(pid)}
	pinSession(session)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session(id).processes[pid] = session
}

// adoptProcesses takes in what the finished command or terminal commandID
// left in the process sessions it led. Call it once that work has finished.
func (r *WorkSessionRegistry) adoptProcesses(id, kind, commandID string) {
	r.mu.Lock()
	s, ok := r.sessions[id]
	var finished []OwnedSession
	if ok {
		for _, session := range s.processes {
			if session.Kind == kind && session.CommandID == commandID {
				finished = append(finished, session)
			}
		}
	}
	r.mu.Unlock()
	for _, session := range finished {
		adoptSession(session)
	}
}

// pruneProcesses drops the owned process sessions that no longer have a
// live member. It reads the process table without r.mu.
func (r *WorkSessionRegistry) pruneProcesses(id string) {
	r.mu.Lock()
	s, ok := r.sessions[id]
	if !ok || len(s.processes) == 0 {
		r.mu.Unlock()
		return
	}
	candidates := s.owned().Sessions
	r.mu.Unlock()

	var dead []int
	for _, process := range candidates {
		if !r.sessionAlive(process) {
			dead = append(dead, process.SID)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[id]; ok {
		for _, sid := range dead {
			delete(s.processes, sid)
		}
	}
}

// syncInventoryLoop starts the periodic inventory of a paused session and
// stops it once the session leaves paused. Call it under r.mu.
func (r *WorkSessionRegistry) syncInventoryLoop(id string, s *trackedWorkSession) {
	switch {
	case s.state == workSessionPaused && s.stopInventory == nil && r.postInventory != nil:
		stop := make(chan struct{})
		s.stopInventory = stop
		go r.runInventoryLoop(id, stop)
	case s.state != workSessionPaused && s.stopInventory != nil:
		close(s.stopInventory)
		s.stopInventory = nil
	}
}

func (r *WorkSessionRegistry) runInventoryLoop(id string, stop <-chan struct{}) {
	ticker := time.NewTicker(r.inventoryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			r.reportInventory(id, true)
		}
	}
}

// reportInventory posts the processes the session owns. With whilePaused it
// posts only when the session is still paused at the revision it read.
func (r *WorkSessionRegistry) reportInventory(id string, whilePaused bool) {
	if r.postInventory == nil {
		return
	}
	lister, ok := r.processes.(processInventory)
	if !ok {
		return
	}
	r.reports.Lock()
	defer r.reports.Unlock()

	r.pruneProcesses(id)
	r.mu.Lock()
	s, ok := r.sessions[id]
	if !ok || whilePaused && s.state != workSessionPaused {
		r.mu.Unlock()
		return
	}
	owned, revision := s.owned(), s.revision
	r.mu.Unlock()

	processes, err := lister.Inventory(owned)
	if err != nil {
		log.Warn().Err(err).Str("work_session_id", id).Msg("Could not list the processes of a work session.")
		return
	}

	r.mu.Lock()
	current, ok := r.sessions[id]
	stillPaused := ok && current.state == workSessionPaused && current.revision == revision
	r.mu.Unlock()
	if whilePaused && !stillPaused {
		return
	}

	inventory := WorkSessionProcessInventory{
		WorkSessionID: id,
		Revision:      protocol.Uint64String(revision),
		ObservedAt:    r.now().UTC().Format(time.RFC3339Nano),
		Processes:     processes,
	}
	if len(inventory.Processes) > workSessionInventoryLimit {
		inventory.Processes, inventory.Truncated = inventory.Processes[:workSessionInventoryLimit], true
	}
	r.postInventory(inventory)
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

// trackTerminalProcess is nil-safe and records the process session of a
// terminal's shell.
func (b *workSessionBinding) trackTerminalProcess(commandID string, pid int) {
	if b != nil {
		b.registry.trackProcess(b.id, ownedKindTerminal, commandID, pid)
	}
}

// TrackWorkSessionProcess records the process session a command started,
// keyed by its leader pid, when the command runs under a Work Session. Its
// children then stay owned after the command finishes.
func TrackWorkSessionProcess(ctx context.Context, commandID string, pid int) {
	if b := workSessionFromContext(ctx); b != nil {
		b.registry.trackProcess(b.id, ownedKindCommand, commandID, pid)
	}
}

// registerTerminal is nil-safe and returns a no-op for session-less terminals.
func (b *workSessionBinding) registerTerminal(terminalID, commandID string) func() {
	if b == nil {
		return func() {}
	}
	return b.registry.registerTerminal(b.id, terminalID, commandID)
}
