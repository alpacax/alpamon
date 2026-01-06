package tunnel

import (
	"context"
	"fmt"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/rs/zerolog/log"
)

// TunnelHandler handles tunnel connection commands (opentunnel, closetunnel)
type TunnelHandler struct {
	*common.BaseHandler
}

// NewTunnelHandler creates a new tunnel handler
func NewTunnelHandler(cmdExecutor common.CommandExecutor) *TunnelHandler {
	h := &TunnelHandler{
		BaseHandler: common.NewBaseHandler(
			common.Tunnel,
			[]common.CommandType{
				common.OpenTunnel,
				common.CloseTunnel,
			},
			cmdExecutor,
		),
	}
	return h
}

// Execute runs the tunnel command
func (h *TunnelHandler) Execute(_ context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.OpenTunnel.String():
		return h.handleOpenTunnel(args)
	case common.CloseTunnel.String():
		return h.handleCloseTunnel(args)
	default:
		return 1, "", fmt.Errorf("unknown tunnel command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *TunnelHandler) Validate(cmd string, args *common.CommandArgs) error {
	switch cmd {
	case common.OpenTunnel.String():
		data := OpenTunnelData{
			SessionID:  args.SessionID,
			URL:        args.URL,
			TargetPort: args.TargetPort,
		}
		if err := h.ValidateStruct(data); err != nil {
			return err
		}
		// Check for duplicate tunnel to prevent process leak
		if _, exists := runner.GetActiveTunnel(args.SessionID); exists {
			return fmt.Errorf("tunnel with session ID %s already exists", args.SessionID)
		}
		return nil

	case common.CloseTunnel.String():
		data := CloseTunnelData{
			SessionID: args.SessionID,
		}
		return h.ValidateStruct(data)

	default:
		return fmt.Errorf("unknown tunnel command: %s", cmd)
	}
}

// handleOpenTunnel opens a new tunnel connection
func (h *TunnelHandler) handleOpenTunnel(args *common.CommandArgs) (int, string, error) {
	err := h.Validate(common.OpenTunnel.String(), args)
	if err != nil {
		return 1, fmt.Sprintf("opentunnel: Not enough information. %s", err.Error()), nil
	}

	log.Info().
		Str("sessionID", args.SessionID).
		Int("targetPort", args.TargetPort).
		Str("url", args.URL).
		Msg("Opening tunnel connection")

	tunnelClient := runner.NewTunnelClient(
		args.SessionID,
		runner.ClientTypeCLI, // TODO: support ClientType from args after editor integration
		args.TargetPort,
		"", // username (for editor type)
		"", // groupname (for editor type)
		args.URL,
	)
	go tunnelClient.RunTunnelBackground()

	return 0, fmt.Sprintf("Tunnel opened for session %s to port %d.", args.SessionID, args.TargetPort), nil
}

// handleCloseTunnel closes an existing tunnel connection
func (h *TunnelHandler) handleCloseTunnel(args *common.CommandArgs) (int, string, error) {
	err := h.Validate(common.CloseTunnel.String(), args)
	if err != nil {
		return 1, fmt.Sprintf("closetunnel: Not enough information. %s", err.Error()), nil
	}

	log.Info().
		Str("sessionID", args.SessionID).
		Msg("Closing tunnel connection")

	err = runner.CloseTunnel(args.SessionID)
	if err != nil {
		return 1, fmt.Sprintf("closetunnel: Failed to close tunnel. %s", err.Error()), nil
	}

	return 0, fmt.Sprintf("Tunnel closed for session %s.", args.SessionID), nil
}
