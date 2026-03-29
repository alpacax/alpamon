package executor

import (
	"fmt"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/executor/handlers/file"
	"github.com/alpacax/alpamon/pkg/executor/handlers/info"
	"github.com/alpacax/alpamon/pkg/executor/handlers/shell"
	"github.com/alpacax/alpamon/pkg/executor/handlers/terminal"
	"github.com/alpacax/alpamon/pkg/executor/services"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/alpacax/alpamon/pkg/scheduler"
)

// SystemInfoCallbacks contains function callbacks for system info operations
type SystemInfoCallbacks struct {
	CommitFunc func()
	SyncFunc   func(*scheduler.Session, []string)
}

// HandlerFactory encapsulates handler instantiation and registration
type HandlerFactory struct {
	dispatcher *CommandDispatcher
	cmdExec    common.CommandExecutor
}

// NewHandlerFactory creates a new handler factory
func NewHandlerFactory(dispatcher *CommandDispatcher, cmdExec common.CommandExecutor) *HandlerFactory {
	return &HandlerFactory{
		dispatcher: dispatcher,
		cmdExec:    cmdExec,
	}
}

// platformHandlerDeps holds dependencies needed by platform-specific handler registration.
type platformHandlerDeps struct {
	cmdExec      common.CommandExecutor
	wsClient     common.WSClient
	ctxManager   *agent.ContextManager
	pool         *pool.Pool
	infoAdapter  *SystemInfoAdapter
	groupService services.GroupService
}

// RegisterAll registers all handlers with the provided callbacks
func (f *HandlerFactory) RegisterAll(
	pool *pool.Pool,
	ctxManager *agent.ContextManager,
	session *scheduler.Session,
	wsClient common.WSClient,
	callbacks SystemInfoCallbacks,
) error {
	// Create group service for dependency injection
	groupService := services.NewDefaultGroupService(f.cmdExec)

	// Create system info adapter for info handler with function callbacks
	infoAdapter := NewSystemInfoAdapter(session, callbacks.CommitFunc, callbacks.SyncFunc)

	// Create terminal manager for PTY session lifecycle
	terminalManager := runner.NewTerminalManager()

	// Cross-platform handlers
	handlers := []common.Handler{
		info.NewInfoHandler(infoAdapter),
		shell.NewShellHandler(f.cmdExec),
		file.NewFileHandler(f.cmdExec, session),
		terminal.NewTerminalHandler(f.cmdExec, session, terminalManager),
	}

	// Platform-specific handlers
	deps := platformHandlerDeps{
		cmdExec:      f.cmdExec,
		wsClient:     wsClient,
		ctxManager:   ctxManager,
		pool:         pool,
		infoAdapter:  infoAdapter,
		groupService: groupService,
	}
	handlers = append(handlers, platformHandlers(deps)...)

	// Register all handlers
	for _, handler := range handlers {
		if err := f.dispatcher.RegisterHandler(handler); err != nil {
			return fmt.Errorf("failed to register handler: %w", err)
		}
	}

	return nil
}
