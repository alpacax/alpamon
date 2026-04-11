package runner

import (
	"fmt"

	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

// PtyClient is a stub on Windows. ConPTY support will be added in a future PR.
type PtyClient struct {
	sessionID string
	manager   *TerminalManager
}

func NewPtyClient(data protocol.CommandData, apiSession *scheduler.Session, manager *TerminalManager) *PtyClient {
	return &PtyClient{
		sessionID: data.SessionID,
		manager:   manager,
	}
}

func (pc *PtyClient) RunPtyBackground() {
	log.Error().Str("sessionID", pc.sessionID).
		Msg("PTY terminal is not yet supported on Windows. ConPTY support coming soon.")
}

func (pc *PtyClient) Resize(rows, cols uint16) error {
	return fmt.Errorf("PTY resize not supported on Windows")
}

func (pc *PtyClient) Refresh() error {
	return fmt.Errorf("PTY refresh not supported on Windows")
}
