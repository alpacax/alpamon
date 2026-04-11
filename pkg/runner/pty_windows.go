package runner

import (
	"context"
	"fmt"
	"strings"

	"github.com/UserExistsError/conpty"
	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// PtyClient manages a ConPTY terminal session on Windows.
type PtyClient struct {
	cpty          *conpty.ConPty
	url           string
	rows          uint16
	cols          uint16
	username      string
	groupname     string
	homeDirectory string
	sessionID     string
	manager       *TerminalManager
	apiSession    *scheduler.Session
}

func NewPtyClient(data protocol.CommandData, apiSession *scheduler.Session, manager *TerminalManager) *PtyClient {
	return &PtyClient{
		apiSession:    apiSession,
		url:           data.URL,
		rows:          data.Rows,
		cols:          data.Cols,
		username:      data.Username,
		groupname:     data.Groupname,
		homeDirectory: data.HomeDirectory,
		sessionID:     data.SessionID,
		manager:       manager,
	}
}

func (pc *PtyClient) RunPtyBackground() {
	log.Debug().Msg("Starting Websh session in background (Windows ConPTY).")

	shell := utils.DefaultShell()
	args := utils.DefaultShellArgs()
	commandLine := shell
	if len(args) > 0 {
		commandLine = shell + " " + strings.Join(args, " ")
	}

	// Build environment
	env := getDefaultEnv()
	env["USER"] = pc.username
	if pc.homeDirectory != "" {
		env["USERPROFILE"] = pc.homeDirectory
	}
	var envSlice []string
	for k, v := range env {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}

	opts := []conpty.ConPtyOption{
		conpty.ConPtyDimensions(int(pc.cols), int(pc.rows)),
		conpty.ConPtyEnv(envSlice),
	}
	if pc.homeDirectory != "" {
		opts = append(opts, conpty.ConPtyWorkDir(pc.homeDirectory))
	}

	cpty, err := conpty.Start(commandLine, opts...)
	if err != nil {
		log.Error().Err(err).Str("sessionID", pc.sessionID).
			Msg("Failed to start ConPTY session.")
		return
	}
	pc.cpty = cpty
	defer func() { _ = cpty.Close() }()

	pc.manager.Register(pc.sessionID, pc)
	defer pc.manager.Remove(pc.sessionID)

	log.Info().Str("sessionID", pc.sessionID).Int("pid", cpty.Pid()).
		Msg("ConPTY session started.")

	// TODO: Implement WebSocket ↔ ConPTY I/O relay.
	// This requires the same channel-based architecture as pty.go's
	// readFromPty/writeToPty/readFromWebsocket/writeToWebsocket,
	// but using cpty.Read()/cpty.Write() instead of ptmx file I/O.
	// For now, wait for the process to exit.
	_, _ = cpty.Wait(context.Background())
	log.Info().Str("sessionID", pc.sessionID).Msg("ConPTY session ended.")
}

func (pc *PtyClient) Resize(rows, cols uint16) error {
	if pc.cpty == nil {
		return fmt.Errorf("ConPTY not initialized")
	}
	return pc.cpty.Resize(int(cols), int(rows))
}

func (pc *PtyClient) Refresh() error {
	// Windows ConPTY does not have a SIGWINCH equivalent.
	return nil
}
