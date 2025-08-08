package runner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/cenkalti/backoff"
	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

type PtyClient struct {
	conn          *websocket.Conn
	apiSession    *scheduler.Session
	requestHeader http.Header
	cmd           *exec.Cmd
	ptmx          *os.File
	url           string
	rows          uint16
	cols          uint16
	username      string
	groupname     string
	homeDirectory string
	sessionID     string
	wsToPty       chan []byte
	ptyToWs       chan []byte
	isRecovering  atomic.Bool // default : false
}

const (
	maxRecoveryTimeout       = 1 * time.Minute
	reconnectPtyWebsocketURL = "/api/websh/pty-channels/"
	bufferSize               = 8192

	sessionCloseCode = 4000
)

var terminals map[string]*PtyClient

func init() {
	terminals = make(map[string]*PtyClient)
}

func NewPtyClient(data CommandData, apiSession *scheduler.Session) *PtyClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
	}

	var finalURL string
	if strings.HasPrefix(data.URL, "ws:") || strings.HasPrefix(data.URL, "wss:") {
		finalURL = data.URL
	} else {
		// For local development
		wsURL := strings.Replace(config.GlobalSettings.ServerURL, "http", "ws", 1)
		wsURL = strings.Replace(wsURL, ":8000", ":8080", 1)

		finalURL = wsURL + data.URL
	}

	return &PtyClient{
		apiSession:    apiSession,
		requestHeader: headers,
		url:           finalURL,
		rows:          data.Rows,
		cols:          data.Cols,
		username:      data.Username,
		groupname:     data.Groupname,
		homeDirectory: data.HomeDirectory,
		sessionID:     data.SessionID,
		wsToPty:       make(chan []byte, bufferSize),
		ptyToWs:       make(chan []byte, bufferSize),
	}
}

func (pc *PtyClient) initializePtySession() error {
	var err error
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
		},
	}
	pc.conn, _, err = dialer.Dial(pc.url, pc.requestHeader)
	if err != nil {
		return fmt.Errorf("failed to connect Websh server: %w", err)
	}

	pc.cmd = exec.Command("/bin/bash", "-i")
	uid, gid, groupIds, env, err := pc.getPtyUserAndEnv()
	if err != nil {
		return fmt.Errorf("failed to get user/env: %w", err)
	}
	pc.setPtyCmdSysProcAttrAndEnv(uid, gid, groupIds, env)

	initialSize := &pty.Winsize{Rows: pc.rows, Cols: pc.cols}
	pc.ptmx, err = pty.StartWithSize(pc.cmd, initialSize)
	if err != nil {
		return fmt.Errorf("failed to start pty: %w", err)
	}

	terminals[pc.sessionID] = pc
	return nil
}

func (pc *PtyClient) RunPtyBackground() {
	log.Debug().Msg("Starting Websh session in background.")
	defer pc.close()

	err := pc.initializePtySession()
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recoveryChan := make(chan struct{}, 1)
	recoveredWsChan := make(chan struct{}, 1)
	recoveredPtyChan := make(chan struct{}, 1)

	go pc.readFromPty(ctx, cancel)
	go pc.writeToWebsocket(ctx, cancel, recoveryChan, recoveredPtyChan)

	go pc.readFromWebsocket(ctx, cancel, recoveryChan, recoveredWsChan)
	go pc.writeToPty(ctx, cancel)

	for {
		select {
		case <-ctx.Done():
			return
		case <-recoveryChan:
			log.Debug().Msg("Attempting to reconnect Websh channel...")
			err = pc.recovery()
			pc.isRecovering.Store(false)
			if err != nil {
				cancel()
				return
			}
			recoveredWsChan <- struct{}{}
			recoveredPtyChan <- struct{}{}
		}
	}
}

func (pc *PtyClient) readFromWebsocket(ctx context.Context, cancel context.CancelFunc, recoveryChan, recoveredChan chan struct{}) {
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

				if pc.isRecovering.CompareAndSwap(false, true) {
					recoveryChan <- struct{}{}
				}
				select {
				case <-recoveredChan:
					continue
				case <-ctx.Done():
					return
				}
			}
			pc.wsToPty <- msg
		}
	}
}

func (pc *PtyClient) writeToPty(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-pc.wsToPty:
			_, err := pc.ptmx.Write(msg)
			if err != nil {
				cancel()
				return
			}
		}
	}
}

func (pc *PtyClient) readFromPty(ctx context.Context, cancel context.CancelFunc) {
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := pc.ptmx.Read(buf)
			if err != nil {
				cancel()
				return
			}
			pc.ptyToWs <- append([]byte(nil), buf[:n]...)
		}
	}
}

func (pc *PtyClient) writeToWebsocket(ctx context.Context, cancel context.CancelFunc, recoveryChan, recoveredChan chan struct{}) {
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
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, sessionCloseCode) {
					log.Debug().Msg("Websh channel closed by peer.")
					cancel()
					return
				}

				if pc.isRecovering.CompareAndSwap(false, true) {
					recoveryChan <- struct{}{}
				}
				select {
				case <-recoveredChan:
					continue
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (pc *PtyClient) resize(rows, cols uint16) error {
	err := pty.Setsize(pc.ptmx, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
	if err != nil {
		log.Warn().Err(err).Msg("Failed to resize terminal.")
		return err
	}
	pc.rows = rows
	pc.cols = cols
	log.Debug().Msgf("Resized terminal for %s to %dx%d.", pc.sessionID, pc.rows, pc.cols)
	return nil
}

// close terminates the PTY session and cleans up resources.
// It ensures that the PTY, command, and WebSocket connection are properly closed.
func (pc *PtyClient) close() {
	if pc.ptmx != nil {
		_ = pc.ptmx.Close()
	}

	if pc.cmd != nil && pc.cmd.Process != nil {
		_ = pc.cmd.Process.Kill()
		_ = pc.cmd.Wait()
	}

	if terminals[pc.sessionID] != nil {
		delete(terminals, pc.sessionID)
	}

	if pc.conn != nil {
		err := pc.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(5*time.Second),
		)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to write close message to Websh channel.")
			return
		}

		err = pc.conn.Close()
		if err != nil {
			log.Debug().Err(err).Msg("Failed to close Websh channel.")
		}
	}

	log.Debug().Msg("Websh channel for pty has been closed.")
}

// recovery reconnects the WebSocket while keeping the PTY session alive.
// Note: recovery doesn't close the existing conn explicitly to avoid breaking the session.
// The goal is to replace a broken connection, not perform a graceful shutdown.
func (pc *PtyClient) recovery() error {
	ctx, cancel := context.WithTimeout(context.Background(), maxRecoveryTimeout)
	defer cancel()

	retryBackoff := backoff.NewExponentialBackOff()
	retryBackoff.InitialInterval = 1 * time.Second
	retryBackoff.MaxInterval = 30 * time.Second
	retryBackoff.MaxElapsedTime = 0 // until ctx timeout
	retryBackoff.RandomizationFactor = 0

	operation := func() error {
		select {
		case <-ctx.Done():
			log.Error().Msg("Websh recovery aborted: timeout reached.")
			return backoff.Permanent(ctx.Err())
		default:
			data := map[string]interface{}{
				"session": pc.sessionID,
			}
			body, statusCode, err := pc.apiSession.Post(reconnectPtyWebsocketURL, data, 5)
			if err != nil || statusCode != http.StatusCreated {
				nextInterval := retryBackoff.NextBackOff()
				log.Warn().Err(err).Msgf("Failed to reconnect Websh channel (status: %d), will try again in %ds.", statusCode, int(nextInterval.Seconds()))
				return fmt.Errorf("reconnect failed: %w", err)
			}

			var resp struct {
				WebsocketURL string `json:"websocket_url"`
			}
			if err = json.Unmarshal(body, &resp); err != nil {
				log.Warn().Err(err).Msg("Failed to parse reconnect response.")
				return fmt.Errorf("unmarshal error: %w", err)
			}
			pc.url = strings.Replace(config.GlobalSettings.ServerURL, "http", "ws", 1) + resp.WebsocketURL

			dialer := websocket.Dialer{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
				},
			}
			conn, _, err := dialer.Dial(pc.url, pc.requestHeader)
			if err != nil {
				log.Warn().Err(err).Msg("Websh reconnect failed.")
				return err
			}

			pc.conn = conn
			log.Debug().Msg("Websh reconnected successfully.")
			return nil
		}
	}

	err := backoff.Retry(operation, backoff.WithContext(retryBackoff, ctx))
	if err != nil {
		return err
	}

	return nil
}

// getPtyUserAndEnv retrieves user information and sets environment variables.
func (pc *PtyClient) getPtyUserAndEnv() (uid, gid int, groupIds []string, env map[string]string, err error) {
	env = getDefaultEnv()

	usr, err := utils.GetSystemUser(pc.username)
	if err != nil {
		return 0, 0, nil, nil, err
	}

	currentUID := os.Geteuid()
	if currentUID != 0 || pc.username == "" {
		env["USER"] = usr.Username
		env["HOME"] = usr.HomeDir
	} else {
		env["USER"] = pc.username
		env["HOME"] = pc.homeDirectory
	}

	uid, err = strconv.Atoi(usr.Uid)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("failed to convert UID: %w", err)
	}

	gid, err = strconv.Atoi(usr.Gid)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("failed to convert GID: %w", err)
	}

	groupIds, err = usr.GroupIds()
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("failed to get group IDs: %w", err)
	}

	return uid, gid, groupIds, env, nil
}
