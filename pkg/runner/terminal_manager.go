package runner

import (
	"errors"
	"sync"
)

// TerminalManager manages PTY session lifecycle in a single place.
type TerminalManager struct {
	mu        sync.RWMutex
	terminals map[string]*PtyClient
}

// NewTerminalManager creates a new TerminalManager.
func NewTerminalManager() *TerminalManager {
	return &TerminalManager{
		terminals: make(map[string]*PtyClient),
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

// Resize resizes the terminal for the given session ID.
func (m *TerminalManager) Resize(sessionID string, rows, cols uint16) error {
	client := m.Get(sessionID)
	if client == nil {
		return errors.New("invalid session ID")
	}
	return client.Resize(rows, cols)
}

// Refresh sends SIGWINCH to the terminal for the given session ID.
func (m *TerminalManager) Refresh(sessionID string) error {
	client := m.Get(sessionID)
	if client == nil {
		return errors.New("invalid session ID")
	}
	return client.Refresh()
}
