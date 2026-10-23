// Package executor provides the command execution framework for Alpamon
package executor

import (
	"fmt"
	"sync"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/rs/zerolog/log"
)

// Registry manages the registration and lookup of command handlers
type Registry struct {
	handlers     map[string]common.Handler // handler name -> handler
	cmdToHandler map[string]common.Handler // command -> handler
	mu           sync.RWMutex
}

// NewRegistry creates a new handler registry
func NewRegistry() *Registry {
	return &Registry{
		handlers:     make(map[string]common.Handler),
		cmdToHandler: make(map[string]common.Handler),
	}
}

// Register adds a new handler to the registry
func (r *Registry) Register(h common.Handler) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := h.Name()

	// Check if handler already exists
	if _, exists := r.handlers[name]; exists {
		return fmt.Errorf("handler already registered: %s", name)
	}

	// Register the handler
	r.handlers[name] = h
	log.Debug().Msgf("Registered handler: %s", name)

	// Map each command to this handler
	for _, cmd := range h.Commands() {
		if existing, exists := r.cmdToHandler[cmd]; exists {
			return fmt.Errorf("command %s already registered to handler %s", cmd, existing.Name())
		}
		r.cmdToHandler[cmd] = h
		log.Debug().Msgf("Registered command %s to handler %s", cmd, name)
	}

	return nil
}

// Get retrieves a handler by command name
func (r *Registry) Get(cmd string) (common.Handler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handler, exists := r.cmdToHandler[cmd]
	if !exists {
		return nil, fmt.Errorf("no handler for command: %s", cmd)
	}

	return handler, nil
}

// IsCommandRegistered checks if a command is registered
func (r *Registry) IsCommandRegistered(cmd string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.cmdToHandler[cmd]
	return exists
}
