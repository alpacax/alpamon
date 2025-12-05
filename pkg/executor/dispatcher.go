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

	// Log command execution
	log.Debug().
		Str("command", cmd).
		Interface("args", args).
		Msg("Executing command")

	// Find the appropriate handler
	handler, err := e.registry.Get(cmd)
	if err != nil {
		log.Warn().
			Str("command", cmd).
			Err(err).
			Msg("No handler found for command")
		return 1, "", fmt.Errorf("no handler found for command: %s", cmd)
	}

	// Validate arguments before execution
	if err := handler.Validate(cmd, args); err != nil {
		log.Error().
			Str("command", cmd).
			Err(err).
			Msg("Command validation failed")
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

// ExecuteWithPool executes a command through the worker pool
func (e *CommandDispatcher) ExecuteWithPool(ctx context.Context, cmd string, args *common.CommandArgs) error {
	return e.pool.Submit(ctx, func() error {
		_, _, err := e.Execute(ctx, cmd, args)
		return err
	})
}

// ExecuteAsync executes a command asynchronously
func (e *CommandDispatcher) ExecuteAsync(cmd string, args *common.CommandArgs, timeout time.Duration) {
	go func() {
		ctx, cancel := e.ctxManager.NewContext(timeout)
		defer cancel()

		exitCode, output, err := e.Execute(ctx, cmd, args)
		if err != nil {
			log.Error().
				Str("command", cmd).
				Int("exitCode", exitCode).
				Str("output", output).
				Err(err).
				Msg("Async command execution failed")
		}
	}()
}

// IsCommandSupported checks if a command is supported
func (e *CommandDispatcher) IsCommandSupported(cmd string) bool {
	return e.registry.IsCommandRegistered(cmd)
}

// HasHandler checks if a handler exists for the given command
// This is an alias for IsCommandSupported to match the CommandExecutor interface
func (e *CommandDispatcher) HasHandler(cmd string) bool {
	return e.registry.IsCommandRegistered(cmd)
}

// GetSupportedCommands returns all supported commands
func (e *CommandDispatcher) GetSupportedCommands() []string {
	return e.registry.ListCommands()
}

// GetHandlers returns all registered handler names
func (e *CommandDispatcher) GetHandlers() []string {
	return e.registry.List()
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

// CommandContext wraps command execution context
type CommandContext struct {
	Command   string              `json:"command"`
	Args      *common.CommandArgs `json:"args"`
	Timestamp time.Time           `json:"timestamp"`
	RequestID string              `json:"request_id,omitempty"`
}

// ExecuteWithContext executes a command with additional context
func (e *CommandDispatcher) ExecuteWithContext(ctx context.Context, cmdCtx CommandContext) (int, string, error) {
	// Add request ID to logs if provided
	if cmdCtx.RequestID != "" {
		log := log.With().Str("requestId", cmdCtx.RequestID).Logger()
		log.Debug().
			Str("command", cmdCtx.Command).
			Interface("args", cmdCtx.Args).
			Time("timestamp", cmdCtx.Timestamp).
			Msg("Executing command with context")
	}

	return e.Execute(ctx, cmdCtx.Command, cmdCtx.Args)
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
