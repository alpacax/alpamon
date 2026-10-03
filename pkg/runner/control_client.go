package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	controlMinConnectInterval = 5 * time.Second
	controlMaxConnectInterval = 60 * time.Second
	controlReadTimeout        = 35 * time.Minute
)

// ControlClient handles WebSocket connection for control messages (sudo_approval, etc.)
type ControlClient struct {
	Conn          *websocket.Conn
	requestHeader http.Header
	mu            sync.Mutex
	connected     bool

	// keepalive belongs to Conn and is replaced with it.
	keepalive *connKeepalive

	// connectBackoff outlives a single Connect call: the escalation after
	// repeated rejections is only visible across reconnects.
	connectBackoff *authBackoff
}

// NewControlClient creates a new ControlClient
func NewControlClient() *ControlClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
		"User-Agent":    {utils.GetUserAgent("alpamon")},
	}

	return &ControlClient{
		requestHeader:  headers,
		connectBackoff: newAuthBackoff(controlMinConnectInterval, controlMaxConnectInterval),
	}
}

// GetWSPath returns the WebSocket URL for control endpoint
func (cc *ControlClient) GetWSPath() string {
	return config.GlobalSettings.ControlWSPath
}

// RunForever maintains the control WebSocket connection and handles messages
func (cc *ControlClient) RunForever(ctx context.Context) {
	if err := cc.Connect(ctx); err != nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			cc.Close()
			return
		default:
			conn, ka := cc.connState()
			if conn == nil {
				if err := cc.Connect(ctx); err != nil {
					return
				}
				continue
			}

			err := conn.SetReadDeadline(time.Now().Add(ka.readTimeoutOr(controlReadTimeout)))
			if err != nil {
				if err = cc.reconnectAfterDrop(ctx); err != nil {
					return
				}
				continue
			}

			_, message, err := conn.ReadMessage()
			if err != nil {
				if ka.expired(err) {
					err = cc.reconnectAfterSilence(ctx, conn, ka)
				} else {
					err = cc.reconnectAfterDrop(ctx)
				}
				if err != nil {
					return
				}
				continue
			}

			cc.HandleMessage(message)
		}
	}
}

// conn returns the current connection, or nil when there is none.
func (cc *ControlClient) conn() *websocket.Conn {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.Conn
}

// connState returns the current connection with its keepalive state.
func (cc *ControlClient) connState() (*websocket.Conn, *connKeepalive) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.Conn, cc.keepalive
}

// reconnectAfterSilence drops a connection whose peer stopped answering and
// dials a new one, sending no close frame (see WebsocketClient.reconnectAfterSilence).
func (cc *ControlClient) reconnectAfterSilence(ctx context.Context, conn *websocket.Conn, ka *connKeepalive) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	log.Warn().Msgf("No response from Alpacon control websocket for %s; reconnecting.", keepaliveTimeout)

	cc.mu.Lock()
	if cc.Conn == conn {
		cc.Conn = nil
		cc.keepalive = nil
		cc.connected = false
	}
	cc.mu.Unlock()

	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debug().Err(err).Msg("Failed to close the unresponsive control websocket connection.")
	}
	ka.stop()

	if err := cc.connectBackoff.waitBeforeRedial(ctx); err != nil {
		return err
	}
	return cc.Connect(ctx)
}

// Connect dials until the connection is established, and returns an error
// only when ctx ends first. Repeated rejections slow it down rather than
// stop it; see connectForever.
func (cc *ControlClient) Connect(ctx context.Context) error {
	wsPath := cc.GetWSPath()
	log.Info().Msgf("Connecting to control websocket at %s...", wsPath)

	return connectForever(ctx, cc.connectBackoff, wsPath, func() error {
		conn, err := dialWebsocket(ctx, wsPath, cc.requestHeader)
		if err != nil {
			return err
		}

		ka := newConnKeepalive()
		watchPongs(conn, ka)

		cc.mu.Lock()
		cc.Conn = conn
		cc.keepalive = ka
		cc.connected = true
		cc.mu.Unlock()

		go pingConn(ctx, conn, ka, keepaliveInterval, cc.conn)

		log.Info().Msg("Control WebSocket connection established.")
		return nil
	})
}

// reconnectAfterDrop closes a connection that failed a read and dials a new
// one, paced by waitAfterDrop.
func (cc *ControlClient) reconnectAfterDrop(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cc.Close()

	if err := cc.connectBackoff.waitAfterDrop(ctx); err != nil {
		return err
	}
	return cc.Connect(ctx)
}

// CloseAndReconnect closes current connection and reconnects
func (cc *ControlClient) CloseAndReconnect(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cc.Close()
	return cc.Connect(ctx)
}

// Close cleanly closes the WebSocket connection
func (cc *ControlClient) Close() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.Conn == nil {
		return
	}

	cc.connected = false
	cc.keepalive.stop()
	cc.keepalive = nil

	err := cc.Conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(5*time.Second),
	)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to write close message to control websocket.")
	}

	_ = cc.Conn.Close()
	cc.Conn = nil
}

// WriteJSON sends JSON data through the WebSocket connection
func (cc *ControlClient) WriteJSON(data any) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.Conn == nil {
		return fmt.Errorf("control WebSocket not connected")
	}

	err := writeJSONWithin(cc.Conn, data)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to write JSON to control websocket.")
		return err
	}
	return nil
}

// IsConnected returns whether the client is connected
func (cc *ControlClient) IsConnected() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.connected && cc.Conn != nil
}

// ControlMessage represents the wrapper message from alpacon-server via Redis
type ControlMessage struct {
	Query string          `json:"query"`
	Data  json.RawMessage `json:"data"`
}

// HandleMessage processes incoming control messages
func (cc *ControlClient) HandleMessage(message []byte) {
	if len(message) == 0 {
		return
	}

	// First, parse the outer control message wrapper
	var ctrlMsg ControlMessage
	err := json.Unmarshal(message, &ctrlMsg)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to unmarshal control message wrapper")
		return
	}

	if ctrlMsg.Query != "control" {
		log.Debug().Str("query", ctrlMsg.Query).Msg("Unknown control message query type")
		return
	}

	// Parse the inner data as SudoApprovalResponse
	var response SudoApprovalResponse
	err = json.Unmarshal(ctrlMsg.Data, &response)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to unmarshal control message data")
		return
	}

	switch response.Type {
	case "sudo_approval_response":
		log.Debug().Msgf("Received sudo_approval_response: %+v", response)
		if authManager != nil {
			// Each failure path logs at its own level inside the handler; a client
			// that already left is a warning, not an error.
			_ = authManager.HandleSudoApprovalResponse(response)
		} else {
			log.Error().Msg("AuthManager not available")
		}
	default:
		log.Debug().Str("type", response.Type).Msg("Unknown control message type")
	}
}
