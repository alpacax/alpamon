package executor

import (
	"fmt"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/executor/handlers/file"
	"github.com/alpacax/alpamon/pkg/executor/handlers/firewall"
	"github.com/alpacax/alpamon/pkg/executor/handlers/group"
	"github.com/alpacax/alpamon/pkg/executor/handlers/info"
	"github.com/alpacax/alpamon/pkg/executor/handlers/shell"
	"github.com/alpacax/alpamon/pkg/executor/handlers/system"
	"github.com/alpacax/alpamon/pkg/executor/handlers/terminal"
	"github.com/alpacax/alpamon/pkg/executor/handlers/user"
	"github.com/alpacax/alpamon/pkg/executor/services"
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

	// Define all handlers in a slice for streamlined registration
	handlers := []common.Handler{
		system.NewSystemHandler(f.cmdExec, wsClient, ctxManager, pool),
		group.NewGroupHandler(f.cmdExec, infoAdapter),
		info.NewInfoHandler(infoAdapter),
		shell.NewShellHandler(f.cmdExec),
		user.NewUserHandler(f.cmdExec, groupService, infoAdapter),
		firewall.NewFirewallHandler(f.cmdExec),
		file.NewFileHandler(f.cmdExec, session),
		terminal.NewTerminalHandler(f.cmdExec, session),
	}

	// Register all handlers
	for _, handler := range handlers {
		if err := f.dispatcher.RegisterHandler(handler); err != nil {
			// Return error with context about which handler failed
			return fmt.Errorf("failed to register handler: %w", err)
		}
	}

	return nil
}
