// Package executor provides the command execution framework for Alpamon
package executor

import (
	"fmt"
	"sync"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
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
	log.Debug().Str("handler", name).Msg("Registered handler")

	// Map each command to this handler
	for _, cmd := range h.Commands() {
		if existing, exists := r.cmdToHandler[cmd]; exists {
			return fmt.Errorf("command %s already registered to handler %s", cmd, existing.Name())
		}
		r.cmdToHandler[cmd] = h
		log.Debug().
			Str("command", cmd).
			Str("handler", name).
			Msg("Registered command")
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

// GetHandler retrieves a handler by handler name
func (r *Registry) GetHandler(name string) (common.Handler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handler, exists := r.handlers[name]
	if !exists {
		return nil, fmt.Errorf("handler not found: %s", name)
	}

	return handler, nil
}

// List returns all registered handlers
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		names = append(names, name)
	}
	return names
}

// ListCommands returns all registered commands
func (r *Registry) ListCommands() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	commands := make([]string, 0, len(r.cmdToHandler))
	for cmd := range r.cmdToHandler {
		commands = append(commands, cmd)
	}
	return commands
}

// IsCommandRegistered checks if a command is registered
func (r *Registry) IsCommandRegistered(cmd string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.cmdToHandler[cmd]
	return exists
}

// Unregister removes a handler from the registry
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	handler, exists := r.handlers[name]
	if !exists {
		return fmt.Errorf("handler not found: %s", name)
	}

	// Remove command mappings
	for _, cmd := range handler.Commands() {
		delete(r.cmdToHandler, cmd)
		log.Debug().
			Str("command", cmd).
			Str("handler", name).
			Msg("Unregistered command")
	}

	// Remove handler
	delete(r.handlers, name)
	log.Debug().Str("handler", name).Msg("Unregistered handler")

	return nil
}

// Clear removes all handlers from the registry
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.handlers = make(map[string]common.Handler)
	r.cmdToHandler = make(map[string]common.Handler)
	log.Debug().Msg("Cleared all handlers from registry")
}
