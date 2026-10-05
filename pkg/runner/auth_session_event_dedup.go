package runner

import (
	"sync"
	"time"
)

// sessionEventRepeatWindow is how long a stored session event suppresses an
// identical one. A PAM stack that runs the hook twice (su-l including su, with
// the hook registered in both) sends the second frame milliseconds after the
// first; the window only has to cover that, not a human typing a second login.
const sessionEventRepeatWindow = 5 * time.Second

// maxSessionEventRepeatEntries caps the events remembered within the window.
// When it is full, a new event is stored without being remembered: a missed
// repeat costs a duplicate record, a dropped login costs audit evidence.
const maxSessionEventRepeatEntries = 1024

// sessionEventKey is every field of a session_event that identifies the PAM
// transaction which sent it. Two genuinely distinct logins differ in at least
// one of them, so each field the frame carries belongs here.
type sessionEventKey struct {
	eventType string
	username  string
	service   string
	rhost     string
	tty       string
	pid       int
	ppid      int
}

// sessionEventRepeats remembers recently stored session events so a repeat of
// one from the same PAM transaction is dropped at intake. The zero value is
// ready to use. State is in memory only, so a restart inside the window can
// let one repeat through.
type sessionEventRepeats struct {
	mu     sync.Mutex
	stored map[sessionEventKey]time.Time
	// now is replaced in tests; nil means time.Now.
	now func() time.Time
}

// isRepeat reports whether req repeats an event stored within the window, and
// otherwise remembers req as stored. An event missing a pid, ppid or tty is
// never a repeat: without them two separate logins by the same user over the
// same service could not be told apart. rhost is empty for every local login,
// so it is compared but not required.
func (r *sessionEventRepeats) isRepeat(req SessionEventRequest) bool {
	key, ok := sessionEventKeyOf(req)
	if !ok {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	if storedAt, ok := r.stored[key]; ok && withinRepeatWindow(storedAt, now) {
		return true
	}

	for k, storedAt := range r.stored {
		if !withinRepeatWindow(storedAt, now) {
			delete(r.stored, k)
		}
	}
	if r.stored == nil {
		r.stored = make(map[sessionEventKey]time.Time)
	}
	if len(r.stored) < maxSessionEventRepeatEntries {
		r.stored[key] = now
	}
	return false
}

// forget drops what isRepeat remembered for req, for an event that was not
// stored after all.
func (r *sessionEventRepeats) forget(req SessionEventRequest) {
	key, ok := sessionEventKeyOf(req)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.stored, key)
}

// sessionEventKeyOf builds the key for req, or reports false when req lacks a
// field the key needs.
func sessionEventKeyOf(req SessionEventRequest) (sessionEventKey, bool) {
	if req.PID <= 0 || req.PPID <= 0 || req.TTY == "" {
		return sessionEventKey{}, false
	}
	return sessionEventKey{
		eventType: req.Type,
		username:  req.Username,
		service:   req.Service,
		rhost:     req.RHost,
		tty:       req.TTY,
		pid:       req.PID,
		ppid:      req.PPID,
	}, true
}

// withinRepeatWindow measures elapsed time with the monotonic reading
// time.Now carries, so a wall-clock step neither stretches nor shrinks the
// window. A negative elapsed time, which only a clock without that reading can
// produce, lets the event through rather than dropping it.
func withinRepeatWindow(storedAt, now time.Time) bool {
	elapsed := now.Sub(storedAt)
	return elapsed >= 0 && elapsed < sessionEventRepeatWindow
}
