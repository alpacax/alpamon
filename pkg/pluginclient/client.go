// Package pluginclient owns the agent-side WebSocket command loop that
// dhcp, dns, proxy (and future) plugins share with alpacon-server.
//
// The flow each plugin used to copy-paste:
//
//  1. Connect via the shared runner.WebsocketClient.
//  2. Enforce a 10 MiB read limit + the standard read deadline.
//  3. Decode each frame, reject anything outside the whitelist of
//     stock queries (ping, config_updated, reconfigure, quit,
//     reconnect, restart).
//  4. Dispatch config_updated to configreceiver.Receiver (modern
//     pull-based path), dispatch the plugin-private reconfigure
//     payload to a plugin-supplied callback (legacy push, kept for
//     the dual-emit rollout window), and handle ping / quit /
//     reconnect / restart inline against the shared WsClient.
//
// All of that lives here so each plugin only needs to bring an
// Applier and (during the rollout window) a small reconfigure
// callback that decodes its own Command.Config-bearing payload.
package pluginclient

import (
	"context"
	"encoding/json"
	"time"

	"github.com/alpacax/alpamon/pkg/configreceiver"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

// MaxMessageSize is the maximum allowed WebSocket message size (10 MiB)
// enforced both at the gorilla connection layer (SetReadLimit) and as a
// secondary guard inside the handler.
const MaxMessageSize = 10 * 1024 * 1024

// validQueries is the whitelist of WS command query types the shared
// dispatcher knows about. Anything else is rejected with a log line
// and no side effect.
var validQueries = map[string]bool{
	"ping":           true,
	"config_updated": true,
	"reconfigure":    true,
	"quit":           true,
	"reconnect":      true,
	"restart":        true,
}

// command is the lean frame the shared dispatcher decodes — Query plus
// Reason. The plugin-private “reconfigure“ payload carries additional
// fields (Config map[string]string) that each plugin re-decodes from
// the raw bytes in its OnReconfigure callback.
type command struct {
	Query  string `json:"query"`
	Reason string `json:"reason,omitempty"`
}

// configUpdatedPayload is the live WS frame alpacon-server sends
// alongside the durable plugin.config.updated.v1 stream event.
type configUpdatedPayload struct {
	PluginConfigID string `json:"plugin_config_id"`
}

// Client is the shared dispatcher. Plugins construct one via New and
// run it for the lifetime of the plugin process.
type Client struct {
	// WsClient is the persistent WebSocket to alpacon-server, owned
	// by the plugin SDK host runtime.
	WsClient *runner.WebsocketClient

	// Receiver handles the modern pull-based config flow.
	Receiver *configreceiver.Receiver

	// PluginName is logged when handling ``restart`` (e.g.
	// "alpamon-dhcp-plugin will restart in 1 second.").
	PluginName string

	// OnReconfigure, if non-nil, is called with the raw WS message
	// when a legacy ``reconfigure`` query arrives. Plugins decode
	// their own Config-bearing payload from the bytes. Nil means
	// the legacy path is disabled — the message is logged and
	// discarded.
	OnReconfigure func(rawMessage []byte)
}

// New wires a Client with the standard configreceiver.Receiver around
// the supplied Applier. “onReconfigure“ may be nil if the plugin
// does not (or no longer) supports the legacy push path.
func New(
	ws *runner.WebsocketClient,
	session *scheduler.Session,
	applier configreceiver.Applier,
	pluginName string,
	onReconfigure func(rawMessage []byte),
) *Client {
	return &Client{
		WsClient:      ws,
		Receiver:      &configreceiver.Receiver{Session: session, Applier: applier},
		PluginName:    pluginName,
		OnReconfigure: onReconfigure,
	}
}

// HandleMessage runs the shared dispatch for one inbound frame. It
// never panics for arbitrary inputs — the readers above feed it
// whatever the WebSocket produces.
func (c *Client) HandleMessage(ctx context.Context, message []byte) {
	if len(message) == 0 {
		return
	}

	if len(message) > MaxMessageSize {
		log.Warn().Int("size", len(message)).Msg("Message too large, rejected")
		return
	}

	var cmd command
	if err := json.Unmarshal(message, &cmd); err != nil {
		preview := string(message)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		log.Error().
			Err(err).
			Int("messageSize", len(message)).
			Str("messagePreview", preview).
			Msg("Failed to unmarshal command")
		return
	}

	if !validQueries[cmd.Query] {
		log.Warn().Str("query", cmd.Query).Msg("Invalid query type")
		return
	}

	switch cmd.Query {
	case "config_updated":
		var payload configUpdatedPayload
		if err := json.Unmarshal(message, &payload); err != nil {
			log.Error().Err(err).Msg("Bad config_updated payload")
			return
		}
		if payload.PluginConfigID == "" {
			log.Error().Msg("config_updated event missing plugin_config_id")
			return
		}
		if c.Receiver == nil {
			log.Warn().Msg("Cannot process config_updated: Receiver is nil")
			return
		}
		go c.Receiver.Handle(ctx, payload.PluginConfigID)
		return

	case "reconfigure":
		if c.OnReconfigure == nil {
			log.Debug().Msg("Legacy reconfigure received but no handler wired; ignoring")
			return
		}
		c.OnReconfigure(message)
		return
	}

	// Remaining cases all require WsClient.
	if c.WsClient == nil {
		log.Warn().Str("query", cmd.Query).Msg("Cannot process command: WsClient is nil")
		return
	}

	switch cmd.Query {
	case "ping":
		if err := c.WsClient.SendPongResponse(); err != nil {
			log.Error().Err(err).Msg("Failed to send pong response")
		}
	case "quit":
		log.Debug().Msgf("Quit requested for reason: %s.", cmd.Reason)
		c.WsClient.ShutDown()
	case "reconnect":
		log.Debug().Msgf("Reconnect requested for reason: %s.", cmd.Reason)
		c.WsClient.Close()
	case "restart":
		log.Info().Msgf("%s will restart in 1 second.", c.PluginName)
		time.AfterFunc(1*time.Second, func() {
			c.WsClient.Restart()
		})
	}
}

func (c *Client) setReadLimit() {
	if c.WsClient == nil || c.WsClient.Conn == nil {
		return
	}
	c.WsClient.Conn.SetReadLimit(MaxMessageSize)
}

// RunForever maintains the WebSocket connection and dispatches every
// inbound frame through HandleMessage until ctx is cancelled or the
// remote sends “quit“.
//
// Cancellation caveat: ``ctx`` interrupts the read loop and post-connect
// reconnect (CloseAndReconnect honours ctx), but the *initial*
// WsClient.Connect call below uses its own internal retry timeout and
// does not honour ctx. A caller cancelling during the very first
// connect attempt should expect the call to return only after that
// attempt completes (or the underlying connect times out). This
// matches the existing runner.WebsocketClient.Connect semantics in
// alpamon and is preserved here for behavioural compatibility.
func (c *Client) RunForever(ctx context.Context) {
	if c.WsClient == nil {
		log.Error().Msg("Cannot run: WsClient is nil")
		return
	}
	c.WsClient.Connect()
	c.setReadLimit()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := c.WsClient.Conn.SetReadDeadline(time.Now().Add(runner.ConnectionReadTimeout))
			if err != nil {
				log.Error().Err(err).Msg("Failed to set read deadline, reconnecting")
				c.WsClient.CloseAndReconnect(ctx)
				c.setReadLimit()
				continue
			}
			_, message, err := c.WsClient.ReadMessage()
			if err != nil {
				c.WsClient.CloseAndReconnect(ctx)
				c.setReadLimit()
				continue
			}
			c.HandleMessage(ctx, message)
		}
	}
}
