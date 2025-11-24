package runner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/cenkalti/backoff"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	minConnectInterval    = 5 * time.Second
	maxConnectInterval    = 60 * time.Second
	ConnectionReadTimeout = 35 * time.Minute
	maxRetryTimeout       = 3 * 24 * time.Hour

	eventCommandAckURL = "/api/events/commands/%s/ack/"
	eventCommandFinURL = "/api/events/commands/%s/fin/"
)

type WebsocketClient struct {
	Conn                 *websocket.Conn
	requestHeader        http.Header
	apiSession           *scheduler.Session
	RestartChan          chan struct{}
	ShutDownChan         chan struct{}
	CollectorRestartChan chan struct{}
	pool                 *pool.Pool
	ctxManager           *agent.ContextManager
}

func NewWebsocketClient(session *scheduler.Session, ctxManager *agent.ContextManager, workerPool *pool.Pool) *WebsocketClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
		"User-Agent":    {utils.GetUserAgent("alpamon")},
	}

	return &WebsocketClient{
		requestHeader:        headers,
		apiSession:           session,
		RestartChan:          make(chan struct{}),
		ShutDownChan:         make(chan struct{}),
		CollectorRestartChan: make(chan struct{}, 1),
		pool:                 workerPool,
		ctxManager:           ctxManager,
	}
}

func (wc *WebsocketClient) RunForever(ctx context.Context) {
	wc.Connect()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := wc.Conn.SetReadDeadline(time.Now().Add(ConnectionReadTimeout))
			if err != nil {
				wc.CloseAndReconnect(ctx)
				continue
			}
			_, message, err := wc.ReadMessage()
			if err != nil {
				wc.CloseAndReconnect(ctx)
				continue
			}
			// Sends "ping" query for Alpacon to verify WebSocket session status without error handling.
			_ = wc.SendPingQuery()
			wc.CommandRequestHandler(message)
		}
	}
}

func (wc *WebsocketClient) SendPingQuery() error {
	pingQuery := map[string]string{"query": "ping"}
	err := wc.WriteJSON(pingQuery)
	if err != nil {
		return err
	}

	return nil
}

func (wc *WebsocketClient) ReadMessage() (messageType int, message []byte, err error) {
	messageType, message, err = wc.Conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}

	return messageType, message, nil
}

func (wc *WebsocketClient) Connect() {
	log.Info().Msgf("Connecting to websocket at %s...", config.GlobalSettings.WSPath)

	ctx, cancel := context.WithTimeout(context.Background(), maxRetryTimeout)
	defer cancel()

	wsBackoff := backoff.NewExponentialBackOff()
	wsBackoff.InitialInterval = minConnectInterval
	wsBackoff.MaxInterval = maxConnectInterval
	wsBackoff.MaxElapsedTime = 0 // No time limit for retries (infinite retry)
	wsBackoff.RandomizationFactor = 0

	operation := func() error {
		select {
		case <-ctx.Done():
			log.Error().Msg("Maximum retry duration reached. Shutting down.")
			return backoff.Permanent(ctx.Err())
		default:
			dialer := websocket.Dialer{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
				},
			}
			conn, _, err := dialer.Dial(config.GlobalSettings.WSPath, wc.requestHeader)
			if err != nil {
				nextInterval := wsBackoff.NextBackOff()
				log.Debug().Err(err).Msgf("Failed to connect to %s, will try again in %ds.", config.GlobalSettings.WSPath, int(nextInterval.Seconds()))
				return err
			}

			wc.Conn = conn
			log.Debug().Msg("Backhaul connection established.")
			return nil
		}
	}

	err := backoff.Retry(operation, backoff.WithContext(wsBackoff, ctx))
	if err != nil {
		os.Exit(1)
		return
	}
}

func (wc *WebsocketClient) CloseAndReconnect(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	wc.Close()
	wc.Connect()
}

// Cleanly close the websocket connection by sending a close message
// Do not close quitChan, as the purpose here is to disconnect the WebSocket,
// not to terminate RunForever.
func (wc *WebsocketClient) Close() {
	if wc.Conn == nil {
		return
	}

	err := wc.Conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(5*time.Second),
	)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to write close message to websocket.")
		return
	}

	_ = wc.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err = wc.Conn.NextReader()
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			break
		}
		if err != nil {
			break
		}
	}

	err = wc.Conn.Close()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to close websocket connection.")
	}
}

func (wc *WebsocketClient) ShutDown() {
	close(wc.ShutDownChan)
}

func (wc *WebsocketClient) Restart() {
	close(wc.RestartChan)
}

func (wc *WebsocketClient) RestartCollector() {
	select {
	case wc.CollectorRestartChan <- struct{}{}:
	default:
		log.Info().Msg("Collector restart already requested, skipping duplicate signal.")
	}
}

func (wc *WebsocketClient) CommandRequestHandler(message []byte) {
	var content Content
	var data CommandData

	if len(message) == 0 {
		return
	}

	err := json.Unmarshal(message, &content)
	if err != nil {
		log.Warn().Err(err).Msgf("Inappropriate message: %s.", string(message))
		return
	}

	if content.Command.Data != "" {
		err = json.Unmarshal([]byte(content.Command.Data), &data)
		if err != nil {
			log.Warn().Err(err).Msgf("Inappropriate message: %s.", string(message))
			return
		}
	}

	switch content.Query {
	case "command":
		scheduler.Rqueue.Post(fmt.Sprintf(eventCommandAckURL, content.Command.ID),
			nil,
			10,
			time.Time{},
		)
		commandRunner := NewCommandRunner(wc, wc.apiSession, content.Command, data)

		// Submit command to pool with context using configured default timeout
		var ctx context.Context
		var cancel context.CancelFunc
		if config.GlobalSettings.PoolDefaultTimeout > 0 {
			ctx, cancel = wc.ctxManager.NewContext(time.Duration(config.GlobalSettings.PoolDefaultTimeout) * time.Second)
		} else {
			// No timeout - task can run indefinitely
			ctx, cancel = wc.ctxManager.NewContext(0)
		}
		err := wc.pool.Submit(ctx, func() error {
			defer cancel()
			return commandRunner.Run(ctx)
		})
		if err != nil {
			cancel()
			log.Error().Err(err).Msgf("Failed to submit command %s to pool", content.Command.ID)
			// Send failure notification
			payload := &commandFin{
				Success:     false,
				Result:      fmt.Sprintf("Failed to submit command: %v", err),
				ElapsedTime: 0,
			}
			scheduler.Rqueue.Post(fmt.Sprintf(eventCommandFinURL, content.Command.ID),
				payload,
				10,
				time.Time{},
			)
		}
	case "quit":
		log.Debug().Msgf("Quit requested for reason: %s.", content.Reason)
		wc.ShutDown()
	case "reconnect":
		log.Debug().Msgf("Reconnect requested for reason: %s.", content.Reason)
		wc.Close()
	default:
		log.Warn().Msgf("Not implemented query: %s.", content.Query)
	}
}

func (wc *WebsocketClient) WriteJSON(data interface{}) error {
	err := wc.Conn.WriteJSON(data)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to write json data to websocket.")
		return err
	}
	return nil
}
