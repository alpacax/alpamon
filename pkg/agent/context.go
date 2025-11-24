// Package agent provides context management for the Alpamon agent.
package agent

import (
	"context"
	"sync"
	"time"
)

// ContextManager manages contexts for the agent, providing
// centralized context creation and cancellation.
type ContextManager struct {
	root   context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
}

// NewContextManager creates a new context manager with a root context.
func NewContextManager() *ContextManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ContextManager{
		root:   ctx,
		cancel: cancel,
	}
}

// NewContext creates a new child context with an optional timeout.
// If timeout is 0 or negative, no timeout is applied.
func (m *ContextManager) NewContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if timeout > 0 {
		return context.WithTimeout(m.root, timeout)
	}
	return context.WithCancel(m.root)
}

// NewContextWithDeadline creates a new child context with a specific deadline.
func (m *ContextManager) NewContextWithDeadline(deadline time.Time) (context.Context, context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return context.WithDeadline(m.root, deadline)
}

// Root returns the root context.
// This should be used sparingly, primarily for operations that need
// to outlive the normal shutdown process.
func (m *ContextManager) Root() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.root
}

// Shutdown cancels the root context, triggering cancellation of all child contexts.
// This should be called during graceful shutdown.
func (m *ContextManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancel()
}

// IsShutdown returns true if the context manager has been shut down.
func (m *ContextManager) IsShutdown() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case <-m.root.Done():
		return true
	default:
		return false
	}
}
