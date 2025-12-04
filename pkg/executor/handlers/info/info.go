package info

import (
	"context"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/rs/zerolog/log"
)

// SystemInfoManager interface for system info operations
type SystemInfoManager interface {
	CommitSystemInfo()
	SyncSystemInfo(keys []string)
}

// InfoHandler handles informational commands like ping, help, commit, sync
type InfoHandler struct {
	*common.BaseHandler
	infoManager SystemInfoManager
}

// NewInfoHandler creates a new info handler
func NewInfoHandler(infoManager SystemInfoManager) *InfoHandler {
	h := &InfoHandler{
		BaseHandler: common.NewBaseHandler(
			common.Info,
			[]common.CommandType{
				common.Ping,
				common.Help,
				common.Commit,
				common.Sync,
			},
			nil, // No command executor needed for these commands
		),
		infoManager: infoManager,
	}
	return h
}

// Execute runs the info command
func (h *InfoHandler) Execute(_ context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.Ping.String():
		return h.handlePing()
	case common.Help.String():
		return h.handleHelp()
	case common.Commit.String():
		return h.handleCommit()
	case common.Sync.String():
		return h.handleSync(args)
	default:
		return 1, "", fmt.Errorf("unknown info command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *InfoHandler) Validate(cmd string, args *common.CommandArgs) error {
	// Most info commands don't require validation
	// Only sync accepts optional Keys parameter
	if cmd == common.Sync.String() {
		// Keys is optional, so no validation needed
		_ = args.Keys
	}
	return nil
}

// handlePing handles the ping command
func (h *InfoHandler) handlePing() (int, string, error) {
	// Return current timestamp in RFC3339 format
	return 0, time.Now().Format(time.RFC3339), nil
}

// handleHelp handles the help command
func (h *InfoHandler) handleHelp() (int, string, error) {
	helpMessage := `
Available commands:

System Control:
  upgrade              - Upgrade Alpamon to the latest version
  update               - Update system packages
  restart [target]     - Restart Alpamon or collector (target: alpamon|collector)
  quit                 - Stop Alpamon gracefully
  byebye               - Completely uninstall Alpamon
  reboot               - Reboot the system
  shutdown             - Shutdown the system

User Management:
  adduser              - Add a new user
  deluser              - Delete a user
  moduser              - Modify user settings

Group Management:
  addgroup             - Add a new group
  delgroup             - Delete a group

Firewall Management:
  firewall             - Manage firewall rules
  firewall-rollback    - Rollback firewall changes
  firewall-reorder-chains - Reorder firewall chains
  firewall-reorder-rules  - Reorder firewall rules

File Operations:
  upload               - Upload files to the server
  download             - Download files from the server

Terminal Operations:
  openpty              - Open a PTY session
  openftp              - Open an FTP session
  resizepty            - Resize PTY terminal

System Information:
  commit               - Commit system information
  sync [keys]          - Synchronize system information
  ping                 - Check agent responsiveness
  help                 - Show this help message

Package Management:
  package install <name>   - Install a system package
  package uninstall <name> - Remove a system package

Shell Commands:
  Any other command will be executed as a shell command
`
	return 0, helpMessage, nil
}

// handleCommit handles the commit command
func (h *InfoHandler) handleCommit() (int, string, error) {
	log.Debug().Msg("Executing commit command")

	// Call through interface
	if h.infoManager != nil {
		h.infoManager.CommitSystemInfo()
	}

	return 0, "Committed system information.", nil
}

// handleSync handles the sync command
func (h *InfoHandler) handleSync(args *common.CommandArgs) (int, string, error) {
	log.Debug().Msg("Executing sync command")

	// Extract keys if provided
	keys := args.Keys

	// Call through interface
	if h.infoManager != nil {
		h.infoManager.SyncSystemInfo(keys)
	}

	return 0, "Synchronized system information.", nil
}
