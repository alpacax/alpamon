package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

// CommandDispatcher manages command execution through registered handlers
type CommandDispatcher struct {
	registry   *Registry
	pool       *pool.Pool
	ctxManager *agent.ContextManager
}

// NewCommandDispatcher creates a new command dispatcher
func NewCommandDispatcher(pool *pool.Pool, ctxManager *agent.ContextManager) *CommandDispatcher {
	return &CommandDispatcher{
		registry:   NewRegistry(),
		pool:       pool,
		ctxManager: ctxManager,
	}
}

// RegisterHandler registers a command handler
func (e *CommandDispatcher) RegisterHandler(h common.Handler) error {
	return e.registry.Register(h)
}

// Execute runs a command with the appropriate handler
func (e *CommandDispatcher) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	// Handle nil args
	if args == nil {
		args = &common.CommandArgs{}
	}

	// Find the appropriate handler
	handler, err := e.registry.Get(cmd)
	if err != nil {
		log.Warn().Err(err).Msgf("No handler found for command: %s", cmd)
		return 1, "", fmt.Errorf("no handler found for command: %s", cmd)
	}

	// Validate arguments before execution
	if err := handler.Validate(cmd, args); err != nil {
		log.Error().Err(err).Msgf("Command %s validation failed", cmd)
		return 1, "", fmt.Errorf("validation failed: %w", err)
	}

	// Execute the command
	startTime := time.Now()
	exitCode, output, err := handler.Execute(ctx, cmd, args)
	duration := time.Since(startTime)

	// Log execution result
	if err != nil {
		log.Error().
			Str("command", cmd).
			Int("exitCode", exitCode).
			Dur("duration", duration).
			Err(err).
			Msg("Command execution failed")
	} else {
		log.Info().
			Str("command", cmd).
			Int("exitCode", exitCode).
			Dur("duration", duration).
			Msg("Command executed successfully")
	}

	return exitCode, output, err
}

// HasHandler checks if a handler exists for the given command
func (e *CommandDispatcher) HasHandler(cmd string) bool {
	return e.registry.IsCommandRegistered(cmd)
}

// Shutdown gracefully shuts down the executor
func (e *CommandDispatcher) Shutdown(timeout time.Duration) error {
	log.Info().Msg("Shutting down executor")

	// Cancel all contexts
	e.ctxManager.Shutdown()

	// Shutdown the pool
	if err := e.pool.Shutdown(timeout); err != nil {
		log.Error().Err(err).Msg("Failed to shutdown pool gracefully")
		return err
	}

	log.Info().Msg("Executor shutdown complete")
	return nil
}

// InitDispatcher initializes and configures the command dispatching system with all handlers
func InitDispatcher(
	pool *pool.Pool,
	ctxManager *agent.ContextManager,
	session *scheduler.Session,
	wsClient common.WSClient,
	callbacks SystemInfoCallbacks,
) (*CommandDispatcher, error) {
	// Create the main command dispatcher
	dispatcher := NewCommandDispatcher(pool, ctxManager)

	// Create command executor for system commands
	cmdExecutor := NewExecutor()

	// Create and register all handlers using the handler factory pattern
	factory := NewHandlerFactory(dispatcher, cmdExecutor)
	err := factory.RegisterAll(pool, ctxManager, session, wsClient, callbacks)
	if err != nil {
		return nil, err
	}

	log.Info().Msg("Dispatcher initialized with handlers")

	return dispatcher, nil
}
