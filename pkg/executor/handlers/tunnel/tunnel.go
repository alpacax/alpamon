package tunnel

import (
	"context"
	"fmt"
	"regexp"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/rs/zerolog/log"
)

// validSessionID restricts session IDs to safe characters to prevent socket path injection.
var validSessionID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

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
		return h.validateOpenTunnel(args)
	case common.CloseTunnel.String():
		return h.validateCloseTunnel(args)
	default:
		return fmt.Errorf("unknown tunnel command: %s", cmd)
	}
}

func (h *TunnelHandler) validateOpenTunnel(args *common.CommandArgs) error {
	clientType := getClientType(args.ClientType)

	data := OpenTunnelData{
		SessionID:  args.SessionID,
		URL:        args.URL,
		ClientType: clientType,
		TargetPort: args.TargetPort,
		Username:   args.Username,
		Groupname:  args.Groupname,
	}
	if err := h.ValidateStruct(data); err != nil {
		return err
	}

	if !validSessionID.MatchString(args.SessionID) {
		return fmt.Errorf("invalid session_id format: must contain only alphanumeric characters, hyphens, and underscores")
	}

	if err := h.validateClientTypeRequirements(clientType, data); err != nil {
		return err
	}

	return nil
}

func (h *TunnelHandler) validateClientTypeRequirements(clientType string, data OpenTunnelData) error {
	switch clientType {
	case runner.ClientTypeCLI, runner.ClientTypeWeb:
		if data.TargetPort < 1 || data.TargetPort > 65535 {
			return fmt.Errorf("target_port is required for %s tunnel (must be 1-65535)", clientType)
		}
	case runner.ClientTypeEditor:
		if data.Username == "" {
			return fmt.Errorf("username is required for editor tunnel")
		}
	}
	return nil
}

func (h *TunnelHandler) validateCloseTunnel(args *common.CommandArgs) error {
	data := CloseTunnelData{
		SessionID: args.SessionID,
	}
	if err := h.ValidateStruct(data); err != nil {
		return err
	}

	if !validSessionID.MatchString(args.SessionID) {
		return fmt.Errorf("invalid session_id format: must contain only alphanumeric characters, hyphens, and underscores")
	}

	return nil
}

// handleOpenTunnel opens a new tunnel connection
func (h *TunnelHandler) handleOpenTunnel(args *common.CommandArgs) (int, string, error) {
	if err := h.Validate(common.OpenTunnel.String(), args); err != nil {
		return 1, fmt.Sprintf("opentunnel: %s", err.Error()), nil
	}

	if err := runner.CheckSystemResources(); err != nil {
		log.Warn().Err(err).Str("sessionID", args.SessionID).Msg("Tunnel creation rejected due to high resource usage.")
		return 1, fmt.Sprintf("opentunnel: %s", err.Error()), nil
	}

	clientType := getClientType(args.ClientType)

	log.Info().
		Str("sessionID", args.SessionID).
		Str("clientType", clientType).
		Int("targetPort", args.TargetPort).
		Str("username", args.Username).
		Str("url", args.URL).
		Msg("Opening tunnel connection")

	tunnelClient := runner.NewTunnelClient(
		args.SessionID,
		clientType,
		args.TargetPort,
		args.Username,
		args.Groupname,
		args.URL,
	)

	// Atomically check and register to prevent duplicate session IDs.
	if !runner.RegisterTunnel(args.SessionID, tunnelClient) {
		return 1, fmt.Sprintf("opentunnel: tunnel with session ID %s already exists", args.SessionID), nil
	}

	go tunnelClient.RunTunnelBackground()

	return 0, formatOpenTunnelMessage(clientType, args), nil
}

func getClientType(clientType string) string {
	if clientType == "" {
		return runner.ClientTypeCLI
	}
	return clientType
}

func formatOpenTunnelMessage(clientType string, args *common.CommandArgs) string {
	if clientType == runner.ClientTypeEditor {
		return fmt.Sprintf("Editor tunnel opened for session %s (user: %s).", args.SessionID, args.Username)
	}
	return fmt.Sprintf("Tunnel opened for session %s to port %d.", args.SessionID, args.TargetPort)
}

// handleCloseTunnel closes an existing tunnel connection
func (h *TunnelHandler) handleCloseTunnel(args *common.CommandArgs) (int, string, error) {
	if err := h.Validate(common.CloseTunnel.String(), args); err != nil {
		return 1, fmt.Sprintf("closetunnel: %s", err.Error()), nil
	}

	log.Info().Str("sessionID", args.SessionID).Msg("Closing tunnel connection")

	if err := runner.CloseTunnel(args.SessionID); err != nil {
		return 1, fmt.Sprintf("closetunnel: Failed to close tunnel. %s", err.Error()), nil
	}

	return 0, fmt.Sprintf("Tunnel closed for session %s.", args.SessionID), nil
}
