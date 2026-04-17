package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/UserExistsError/conpty"
	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	bufferSize       = 8192
	sessionCloseCode = 4000
)

// PtyClient manages a ConPTY terminal session on Windows.
type PtyClient struct {
	conn          *websocket.Conn
	apiSession    *scheduler.Session
	requestHeader http.Header
	cpty          *conpty.ConPty
	url           string
	rows          uint16
	cols          uint16
	username      string
	groupname     string
	homeDirectory string
	sessionID     string
	wsToPty       chan []byte
	ptyToWs       chan []byte
	isRecovering  atomic.Bool
	manager       *TerminalManager
}

func NewPtyClient(data protocol.CommandData, apiSession *scheduler.Session, manager *TerminalManager) *PtyClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
	}

	return &PtyClient{
		apiSession:    apiSession,
		requestHeader: headers,
		url:           data.URL,
		rows:          data.Rows,
		cols:          data.Cols,
		username:      data.Username,
		groupname:     data.Groupname,
		homeDirectory: data.HomeDirectory,
		sessionID:     data.SessionID,
		wsToPty:       make(chan []byte, bufferSize),
		ptyToWs:       make(chan []byte, bufferSize),
		manager:       manager,
	}
}

func (pc *PtyClient) RunPtyBackground() {
	log.Debug().Msg("Starting Websh session in background (Windows ConPTY).")
	defer pc.close()

	if err := pc.initializeSession(); err != nil {
		log.Error().Err(err).Str("sessionID", pc.sessionID).Str("username", pc.username).
			Msg("Failed to initialize PTY session.")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pc.readFromPty(ctx, cancel)
	go pc.writeToWebsocket(ctx, cancel)
	go pc.readFromWebsocket(ctx, cancel)
	go pc.writeToPty(ctx, cancel)
	go pc.waitForChildExit(ctx, cancel)

	<-ctx.Done()
}

// waitForChildExit cancels the session when the shell inside the
// ConPTY exits (e.g. the user types `exit` in PowerShell). ConPTY's
// output pipe stays open across the child exit, so Read() alone does
// not notice — without this the websocket would linger until the
// client disconnects or idle-timeouts elsewhere fire. conpty.Wait
// polls WaitForSingleObject on the child process handle.
func (pc *PtyClient) waitForChildExit(ctx context.Context, cancel context.CancelFunc) {
	if pc.cpty == nil {
		return
	}
	exitCode, err := pc.cpty.Wait(ctx)
	if ctx.Err() != nil {
		// Context was already canceled by another goroutine (read
		// error, websocket close, etc.). Nothing to do.
		return
	}
	if err != nil {
		log.Debug().Err(err).Str("sessionID", pc.sessionID).Msg("ConPTY wait returned an error.")
	} else {
		log.Info().Uint32("exitCode", exitCode).Str("sessionID", pc.sessionID).
			Msg("ConPTY child shell exited; closing Websh session.")
	}
	cancel()
}

func (pc *PtyClient) initializeSession() error {
	sanitizedURL, err := validateWebSocketURL(pc.url)
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
		},
	}
	pc.conn, _, err = dialer.Dial(sanitizedURL, pc.requestHeader)
	if err != nil {
		return fmt.Errorf("failed to connect Websh server: %w", err)
	}

	// Build command line
	shell := utils.DefaultShell()
	args := utils.DefaultShellArgs()
	commandLine := shell
	if len(args) > 0 {
		commandLine = shell + " " + strings.Join(args, " ")
	}

	// Inherit the parent process environment so PowerShell has the
	// Windows-specific variables it needs (SystemRoot, PSModulePath,
	// COMPUTERNAME, etc.). Missing these causes error 8009001d at
	// PowerShell startup. Filter out existing USER/USERPROFILE so our
	// overrides don't end up as duplicate keys in the conpty env.
	envSlice := filterEnv(os.Environ(), "USER", "USERPROFILE")
	envSlice = append(envSlice, "USER="+pc.username)
	if pc.homeDirectory != "" {
		envSlice = append(envSlice, "USERPROFILE="+pc.homeDirectory)
	}

	opts := []conpty.ConPtyOption{
		conpty.ConPtyDimensions(int(pc.cols), int(pc.rows)),
		conpty.ConPtyEnv(envSlice),
	}
	if pc.homeDirectory != "" {
		opts = append(opts, conpty.ConPtyWorkDir(pc.homeDirectory))
	}

	pc.cpty, err = conpty.Start(commandLine, opts...)
	if err != nil {
		return fmt.Errorf("failed to start ConPTY: %w", err)
	}

	pc.manager.Register(pc.sessionID, pc)

	log.Info().Str("sessionID", pc.sessionID).Int("pid", pc.cpty.Pid()).
		Msg("ConPTY session started.")
	return nil
}

func (pc *PtyClient) readFromPty(ctx context.Context, cancel context.CancelFunc) {
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := pc.cpty.Read(buf)
			if err != nil {
				cancel()
				return
			}
			data := append([]byte(nil), buf[:n]...)
			select {
			case pc.ptyToWs <- data:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (pc *PtyClient) writeToPty(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-pc.wsToPty:
			_, err := pc.cpty.Write(msg)
			if err != nil {
				cancel()
				return
			}
		}
	}
}

func (pc *PtyClient) readFromWebsocket(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, msg, err := pc.conn.ReadMessage()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, sessionCloseCode) {
					log.Debug().Msg("Websh channel closed by peer.")
					cancel()
					return
				}
				// On Windows, skip WebSocket recovery for simplicity.
				cancel()
				return
			}
			pc.wsToPty <- msg
		}
	}
}

func (pc *PtyClient) writeToWebsocket(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-pc.ptyToWs:
			err := pc.conn.WriteMessage(websocket.BinaryMessage, msg)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				cancel()
				return
			}
		}
	}
}

// filterEnv returns a copy of env with entries whose key is in
// excludeKeys removed. Used to drop inherited parent-process values
// before re-setting them, so the child sees one definitive entry per
// key instead of two. Key comparison is case-insensitive so that
// Windows-style inherited keys (e.g. "Userprofile=…") are caught
// just like "USERPROFILE=…".
func filterEnv(env []string, excludeKeys ...string) []string {
	filtered := make([]string, 0, len(env))
outer:
	for _, e := range env {
		key, _, found := strings.Cut(e, "=")
		if !found {
			filtered = append(filtered, e)
			continue
		}
		for _, excludeKey := range excludeKeys {
			if strings.EqualFold(key, excludeKey) {
				continue outer
			}
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func (pc *PtyClient) close() {
	if pc.cpty != nil {
		_ = pc.cpty.Close()
	}
	if pc.conn != nil {
		_ = pc.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(sessionCloseCode, ""),
			time.Now().Add(5*time.Second),
		)
		_ = pc.conn.Close()
	}
	pc.manager.Remove(pc.sessionID)
	log.Debug().Msg("Websh ConPTY session closed.")
}

func (pc *PtyClient) Resize(rows, cols uint16) error {
	if pc.cpty == nil {
		return fmt.Errorf("ConPTY not initialized")
	}
	if err := pc.cpty.Resize(int(cols), int(rows)); err != nil {
		return err
	}
	pc.rows = rows
	pc.cols = cols
	log.Debug().Msgf("Resized ConPTY for %s to %dx%d.", pc.sessionID, rows, cols)
	return nil
}

func (pc *PtyClient) Refresh() error {
	// Windows ConPTY does not have a SIGWINCH equivalent.
	return nil
}
