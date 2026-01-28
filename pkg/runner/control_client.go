package runner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/cenkalti/backoff"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	controlWSPath             = "/ws/servers/control/"
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
}

// NewControlClient creates a new ControlClient
func NewControlClient() *ControlClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
		"User-Agent":    {utils.GetUserAgent("alpamon")},
	}

	return &ControlClient{
		requestHeader: headers,
	}
}

// GetWSPath returns the WebSocket URL for control endpoint
func (cc *ControlClient) GetWSPath() string {
	// Build control WebSocket path from server URL
	serverURL := config.GlobalSettings.ServerURL
	wsURL := serverURL
	if len(wsURL) > 0 {
		// Replace http with ws
		if wsURL[0:5] == "https" {
			wsURL = "wss" + wsURL[5:]
		} else if wsURL[0:4] == "http" {
			wsURL = "ws" + wsURL[4:]
		}
	}
	return wsURL + controlWSPath
}

// RunForever maintains the control WebSocket connection and handles messages
func (cc *ControlClient) RunForever(ctx context.Context) {
	cc.Connect()

	for {
		select {
		case <-ctx.Done():
			cc.Close()
			return
		default:
			if cc.Conn == nil {
				cc.Connect()
				continue
			}

			err := cc.Conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
			if err != nil {
				cc.CloseAndReconnect(ctx)
				continue
			}

			_, message, err := cc.Conn.ReadMessage()
			if err != nil {
				cc.CloseAndReconnect(ctx)
				continue
			}

			cc.HandleMessage(message)
		}
	}
}

// Connect establishes WebSocket connection to control endpoint
func (cc *ControlClient) Connect() {
	wsPath := cc.GetWSPath()
	log.Info().Msgf("Connecting to control websocket at %s...", wsPath)

	wsBackoff := backoff.NewExponentialBackOff()
	wsBackoff.InitialInterval = controlMinConnectInterval
	wsBackoff.MaxInterval = controlMaxConnectInterval
	wsBackoff.MaxElapsedTime = 0 // Infinite retry
	wsBackoff.RandomizationFactor = 0

	operation := func() error {
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
			},
		}
		conn, _, err := dialer.Dial(wsPath, cc.requestHeader)
		if err != nil {
			nextInterval := wsBackoff.NextBackOff()
			log.Debug().Err(err).Msgf("Failed to connect to control endpoint %s, will try again in %ds.", wsPath, int(nextInterval.Seconds()))
			return err
		}

		cc.mu.Lock()
		cc.Conn = conn
		cc.connected = true
		cc.mu.Unlock()

		log.Info().Msg("Control WebSocket connection established.")
		return nil
	}

	_ = backoff.Retry(operation, wsBackoff)
}

// CloseAndReconnect closes current connection and reconnects
func (cc *ControlClient) CloseAndReconnect(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	cc.Close()
	cc.Connect()
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
func (cc *ControlClient) WriteJSON(data interface{}) error {
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
			err := authManager.HandleSudoApprovalResponse(response)
			if err != nil {
				log.Error().Err(err).Msg("Failed to handle sudo approval response")
			}
		} else {
			log.Error().Msg("AuthManager not available")
		}
	default:
		log.Debug().Str("type", response.Type).Msg("Unknown control message type")
	}
}
