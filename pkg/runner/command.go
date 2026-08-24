package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
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

// newChunkCallback returns the streaming callback for this command, or nil when
// there is no command ID to stream against.
func (cr *CommandRunner) newChunkCallback(ctx context.Context) func(content string) {
	if cr.command.ID == "" {
		return nil
	}

	chunkURL := fmt.Sprintf(eventCommandChunkURL, cr.command.ID)
	// Runner owns seq so chunks across shell operators share one series.
	var seq int
	return func(content string) {
		// Advance seq before Post so it stays monotonic even if Post
		// panics; a reused seq would collide server-side on (command, seq).
		s := seq
		seq++
		scheduler.Rqueue.PostChunk(ctx, chunkURL, &protocol.CommandChunk{
			Seq:     s,
			Content: content,
		}, 10)
	}
}

func (cr *CommandRunner) Run(ctx context.Context) error {
	var exitCode int
	var result string
	start := time.Now()

	defer func() {
		if cr.command.ID != "" {
			finURL := fmt.Sprintf(eventCommandFinURL, cr.command.ID)
			payload := protocol.NewCommandResponse(exitCode == 0, result, time.Since(start).Seconds(), exitCode)
			// Best-effort hint only (retries and concurrent reporters can
			// still race); server must reassemble via seq.
			scheduler.Rqueue.Post(finURL, payload, 11, time.Time{})
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
		if args != nil {
			args.CommandID = cr.command.ID
		}
	case "system":
		command = common.ShellCmd.String()
		args = &common.CommandArgs{
			CommandID:     cr.command.ID,
			Command:       cr.command.Line,
			Username:      cr.command.User,
			Groupname:     cr.command.Group,
			Env:           cr.command.Env,
			AllowSh:       cr.command.AllowSh,
			ChunkCallback: cr.newChunkCallback(ctx),
		}
	case "file":
		// The structured payload in Data is the instruction; Line only renders
		// it for humans. Nothing runs until the file's digest matches.
		fileArgs, refusal := cr.prepareFileCommand(ctx)
		if refusal != nil {
			event := log.Warn().
				Str("command_id", cr.command.ID).
				Str("code", refusal.code).
				Err(refusal.err)
			// Only the local log learns what the file hashed to; the result
			// string the requester reads must not carry it.
			var mismatch *hashMismatchError
			if errors.As(refusal.err, &mismatch) {
				event = event.Str("observed_digest", mismatch.Observed())
			}
			event.Msg("Refused file command")
			exitCode = 1
			result = refusal.String()
			return nil
		}
		defer func() { _ = fileArgs.VerifiedFile.Close() }()
		command = common.ExecFile.String()
		args = fileArgs
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
