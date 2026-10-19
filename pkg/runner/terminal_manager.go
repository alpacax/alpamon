package runner

import (
	"errors"
	"sync"

	"github.com/rs/zerolog/log"
)

// TerminalManager manages PTY session lifecycle in a single place.
type TerminalManager struct {
	mu        sync.RWMutex
	terminals map[string]*PtyClient
	auth      *AuthManager
}

// NewTerminalManager creates a TerminalManager whose PTY sessions register their
// shell PIDs with auth. A nil auth disables that tracking; see trackPID.
func NewTerminalManager(auth *AuthManager) *TerminalManager {
	return &TerminalManager{
		terminals: make(map[string]*PtyClient),
		auth:      auth,
	}
}

// Register adds a PtyClient to the manager.
func (m *TerminalManager) Register(sessionID string, client *PtyClient) {
	m.mu.Lock()
	m.terminals[sessionID] = client
	m.mu.Unlock()
}

// Get returns the PtyClient for the given session ID, or nil if not found.
func (m *TerminalManager) Get(sessionID string) *PtyClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.terminals[sessionID]
}

// Remove deletes a PtyClient from the manager.
func (m *TerminalManager) Remove(sessionID string) {
	m.mu.Lock()
	delete(m.terminals, sessionID)
	m.mu.Unlock()
}

// trackPID maps a session's shell pid on auth, so a sudo inside the session
// resolves to it. A no-op when auth is nil (sudo approval not wired up).
func (m *TerminalManager) trackPID(pid int, session *SessionInfo) {
	if m.auth == nil {
		return
	}
	m.auth.AddPIDSessionMapping(pid, session)
	log.Debug().Msgf("PID mapping added: %d -> Session: %s", pid, session.SessionID)
}

// untrackPID removes the mapping trackPID added. A no-op when auth is nil.
func (m *TerminalManager) untrackPID(pid int) {
	if m.auth == nil {
		return
	}
	m.auth.RemovePIDSessionMapping(pid)
}

// Resize resizes the terminal for the given session ID.
// It holds a read lock for the duration of the resize syscall so that a
// concurrent close/Remove cannot tear down the PTY mid-operation.
func (m *TerminalManager) Resize(sessionID string, rows, cols uint16) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client := m.terminals[sessionID]
	if client == nil {
		return errors.New("invalid session ID")
	}
	return client.Resize(rows, cols)
}

// Refresh sends SIGWINCH to the terminal for the given session ID.
// It holds a read lock for the duration of the signal syscall so that a
// concurrent close/Remove cannot tear down the PTY mid-operation.
func (m *TerminalManager) Refresh(sessionID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client := m.terminals[sessionID]
	if client == nil {
		return errors.New("invalid session ID")
	}
	return client.Refresh()
}
