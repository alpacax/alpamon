package runner

import (
	"context"
	"encoding/json"
	"fmt"
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
			conn := cc.conn()
			if conn == nil {
				if err := cc.Connect(ctx); err != nil {
					return
				}
				continue
			}

			err := conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
			if err != nil {
				if err = cc.CloseAndReconnect(ctx); err != nil {
					return
				}
				continue
			}

			_, message, err := conn.ReadMessage()
			if err != nil {
				if err = cc.CloseAndReconnect(ctx); err != nil {
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

// Connect dials until the connection is established, and returns an error
// only when ctx ends first. Repeated rejections slow it down rather than
// stop it; see connectForever.
func (cc *ControlClient) Connect(ctx context.Context) error {
	wsPath := cc.GetWSPath()
	log.Info().Msgf("Connecting to control websocket at %s...", wsPath)

	return connectForever(ctx, cc.connectBackoff, wsPath, func() error {
		conn, err := dialWebsocket(wsPath, cc.requestHeader)
		if err != nil {
			return err
		}

		cc.mu.Lock()
		cc.Conn = conn
		cc.connected = true
		cc.mu.Unlock()

		log.Info().Msg("Control WebSocket connection established.")
		return nil
	})
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

	err := cc.Conn.WriteJSON(data)
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
