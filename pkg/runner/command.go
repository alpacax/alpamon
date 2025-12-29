package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

// CommandDispatcher interface to avoid circular import with executor package
type CommandDispatcher interface {
	Execute(ctx context.Context, command string, args *common.CommandArgs) (int, string, error)
	HasHandler(command string) bool
}

// CommandRunner executes commands received from the server
type CommandRunner struct {
	name       string
	command    protocol.Command
	wsClient   *WebsocketClient
	apiSession *scheduler.Session
	data       protocol.CommandData
	dispatcher CommandDispatcher
}

func NewCommandRunner(wsClient *WebsocketClient, apiSession *scheduler.Session, command protocol.Command, data protocol.CommandData, dispatcher CommandDispatcher) *CommandRunner {
	var name string
	if command.ID != "" {
		name = fmt.Sprintf("CommandRunner-%s", strings.Split(command.ID, "-")[0])
	}

	return &CommandRunner{
		name:       name,
		command:    command,
		data:       data,
		wsClient:   wsClient,
		apiSession: apiSession,
		dispatcher: dispatcher,
	}
}

func (cr *CommandRunner) Run(ctx context.Context) error {
	var exitCode int
	var result string
	start := time.Now()

	defer func() {
		if cr.command.ID != "" {
			finURL := fmt.Sprintf(eventCommandFinURL, cr.command.ID)
			payload := protocol.NewCommandResponse(exitCode == 0, result, time.Since(start).Seconds())
			scheduler.Rqueue.Post(finURL, payload, 10, time.Time{})
		}
	}()

	log.Debug().Msgf("Received command: %s > %s", cr.command.Shell, cr.command.Line)

	// Check if context is already cancelled before starting
	select {
	case <-ctx.Done():
		result = fmt.Sprintf("Command cancelled before execution: %v", ctx.Err())
		exitCode = 1
		return fmt.Errorf("command failed with exit code %d: %s", exitCode, result)
	default:
	}

	// Check if dispatcher is available
	if cr.dispatcher == nil {
		exitCode = 1
		result = "Internal error: dispatcher not initialized"
		return nil
	}

	var command string
	var args *common.CommandArgs

	switch cr.command.Shell {
	case "internal":
		fields := strings.Fields(cr.command.Line)
		if len(fields) == 0 {
			exitCode = 1
			result = "No command provided"
			return nil
		}
		command = fields[0]
		args = cr.data.ToArgs()
	case "system":
		command = common.ShellCmd.String()
		args = &common.CommandArgs{
			Command:   cr.command.Line,
			Username:  cr.command.User,
			Groupname: cr.command.Group,
			Env:       cr.command.Env,
		}
	default:
		exitCode = 1
		result = "Invalid command shell argument."
		return nil
	}

	// Check if handler exists for the command
	if !cr.dispatcher.HasHandler(command) {
		exitCode = 1
		result = fmt.Sprintf("Unknown command: %s", command)
		return nil
	}

	log.Debug().Msgf("Executing %s command: %s", cr.command.Shell, command)

	var err error
	exitCode, result, err = cr.dispatcher.Execute(ctx, command, args)
	if err != nil {
		log.Error().Err(err).Str("command", command).Msg("Command execution failed")
	}

	return nil
}
