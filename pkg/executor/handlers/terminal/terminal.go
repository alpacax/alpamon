package terminal

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// TerminalHandler handles PTY and FTP terminal commands
type TerminalHandler struct {
	*common.BaseHandler
	apiSession *scheduler.Session
}

// NewTerminalHandler creates a new terminal handler
func NewTerminalHandler(cmdExecutor common.CommandExecutor, apiSession *scheduler.Session) *TerminalHandler {
	h := &TerminalHandler{
		BaseHandler: common.NewBaseHandler(
			common.Terminal,
			[]common.CommandType{
				common.OpenPty,
				common.OpenFtp,
				common.ResizePty,
			},
			cmdExecutor,
		),
		apiSession: apiSession,
	}
	return h
}

// Execute runs the terminal command
func (h *TerminalHandler) Execute(_ context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.OpenPty.String():
		return h.handleOpenPTY(args)
	case common.OpenFtp.String():
		return h.handleOpenFTP(args)
	case common.ResizePty.String():
		return h.handleResizePTY(args)
	default:
		return 1, "", fmt.Errorf("unknown terminal command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *TerminalHandler) Validate(cmd string, args *common.CommandArgs) error {
	switch cmd {
	case common.OpenPty.String():
		data := PTYData{
			SessionID:     args.SessionID,
			URL:           args.URL,
			Username:      args.Username,
			Groupname:     args.Groupname,
			HomeDirectory: args.HomeDirectory,
			Rows:          int(args.Rows),
			Cols:          int(args.Cols),
		}
		return h.ValidateStruct(data)

	case common.OpenFtp.String():
		data := FTPData{
			SessionID:     args.SessionID,
			URL:           args.URL,
			Username:      args.Username,
			Groupname:     args.Groupname,
			HomeDirectory: args.HomeDirectory,
		}
		return h.ValidateStruct(data)

	case common.ResizePty.String():
		data := ResizePTYData{
			SessionID: args.SessionID,
			Rows:      int(args.Rows),
			Cols:      int(args.Cols),
		}
		return h.ValidateStruct(data)

	default:
		return fmt.Errorf("unknown terminal command: %s", cmd)
	}
}

// handleOpenPTY opens a new PTY terminal session
func (h *TerminalHandler) handleOpenPTY(args *common.CommandArgs) (int, string, error) {
	err := h.Validate(common.OpenPty.String(), args)
	if err != nil {
		return 1, fmt.Sprintf("openpty: Not enough information. %s", err.Error()), nil
	}

	data := runner.CommandData{
		SessionID:     args.SessionID,
		URL:           args.URL,
		Username:      args.Username,
		Groupname:     args.Groupname,
		HomeDirectory: args.HomeDirectory,
		Rows:          uint16(args.Rows),
		Cols:          uint16(args.Cols),
	}

	log.Info().
		Str("sessionID", data.SessionID).
		Str("username", data.Username).
		Uint16("rows", data.Rows).
		Uint16("cols", data.Cols).
		Msg("Opening PTY terminal")

	ptyClient := runner.NewPtyClient(data, h.apiSession)
	go ptyClient.RunPtyBackground()

	return 0, "Spawned a pty terminal.", nil
}

// handleOpenFTP opens a new FTP session
func (h *TerminalHandler) handleOpenFTP(args *common.CommandArgs) (int, string, error) {
	err := h.Validate(common.OpenFtp.String(), args)
	if err != nil {
		return 1, fmt.Sprintf("openftp: Not enough information. %s", err.Error()), nil
	}

	log.Info().
		Str("sessionID", args.SessionID).
		Str("username", args.Username).
		Str("url", args.URL).
		Msg("Opening FTP session")

	result, err := utils.Demote(args.Username, args.Groupname, utils.DemoteOptions{ValidateGroup: false})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get demote permission")
		return 1, fmt.Sprintf("openftp: Failed to get demoted permission. %v", err), nil
	}

	var sysProcAttr = result.SysProcAttr
	var homeDirectory string
	if result != nil && result.User != nil {
		homeDirectory = result.User.HomeDir
	}

	executable, err := os.Executable()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get executable path")
		return 1, fmt.Sprintf("openftp: Failed to get executable path. %v", err), nil
	}

	cmd := exec.Command(
		executable,
		"ftp",
		args.URL,
		config.GlobalSettings.ServerURL,
		homeDirectory,
	)
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to start ftp worker process")
		return 1, fmt.Sprintf("openftp: Failed to start ftp worker process. %v", err), nil
	}

	go func() { _ = cmd.Wait() }()

	return 0, "Spawned a ftp terminal.", nil
}

// handleResizePTY resizes a PTY terminal
func (h *TerminalHandler) handleResizePTY(args *common.CommandArgs) (int, string, error) {
	log.Info().
		Str("sessionID", args.SessionID).
		Int("rows", int(args.Rows)).
		Int("cols", int(args.Cols)).
		Msg("Resizing PTY")

	terminal := runner.GetTerminal(args.SessionID)
	if terminal == nil {
		return 1, "Invalid session ID", nil
	}

	err := terminal.Resize(uint16(args.Rows), uint16(args.Cols))
	if err != nil {
		return 1, err.Error(), nil
	}

	return 0, fmt.Sprintf("Resized terminal for %s to %dx%d.", args.SessionID, args.Cols, args.Rows), nil
}
