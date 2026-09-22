package pluginclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMessage_RejectsEmptyAndOversized(t *testing.T) {
	c := &Client{}

	for _, size := range []int{0, MaxMessageSize + 1} {
		assert.NotPanics(t, func() {
			c.HandleMessage(context.Background(), make([]byte, size))
		})
	}
}

func TestHandleMessage_RejectsUnknownQuery(t *testing.T) {
	called := false
	c := &Client{
		OnReconfigure: func(_ []byte) { called = true },
	}
	for _, q := range []string{"", "SELECT * FROM users", "rm -rf /", "../../etc/passwd"} {
		msg, _ := json.Marshal(map[string]string{"query": q})
		assert.NotPanics(t, func() {
			c.HandleMessage(context.Background(), msg)
		})
	}
	assert.False(t, called, "OnReconfigure must not fire for unknown queries")
}

func TestHandleMessage_RejectsMalformedJSON(t *testing.T) {
	c := &Client{}
	for _, payload := range [][]byte{[]byte("{not json"), []byte(`{"query": 42}`)} {
		assert.NotPanics(t, func() {
			c.HandleMessage(context.Background(), payload)
		})
	}
}

func TestHandleMessage_ConfigUpdated_RejectsMissingID(t *testing.T) {
	c := &Client{}
	msg, _ := json.Marshal(map[string]string{
		"query":            "config_updated",
		"plugin_config_id": "",
	})
	assert.NotPanics(t, func() {
		c.HandleMessage(context.Background(), msg)
	})
}

func TestHandleMessage_ConfigUpdated_RejectsWhenReceiverNil(t *testing.T) {
	c := &Client{Receiver: nil}
	msg, _ := json.Marshal(map[string]string{
		"query":            "config_updated",
		"plugin_config_id": "abc-123",
	})
	assert.NotPanics(t, func() {
		c.HandleMessage(context.Background(), msg)
	})
}

func TestHandleMessage_LegacyReconfigure_InvokesCallback(t *testing.T) {
	var (
		mu      sync.Mutex
		seenMsg []byte
	)
	c := &Client{
		OnReconfigure: func(raw []byte) {
			mu.Lock()
			defer mu.Unlock()
			seenMsg = append(seenMsg[:0], raw...)
		},
	}
	msg, _ := json.Marshal(map[string]any{
		"query":  "reconfigure",
		"config": map[string]string{"dhcpd.conf": "subnet 10.0.0.0 netmask 255.0.0.0 {}"},
	})
	c.HandleMessage(context.Background(), msg)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, string(msg), string(seenMsg))
}

func TestHandleMessage_LegacyReconfigure_NoopWithoutCallback(t *testing.T) {
	c := &Client{} // OnReconfigure nil
	msg, _ := json.Marshal(map[string]string{"query": "reconfigure"})
	assert.NotPanics(t, func() {
		c.HandleMessage(context.Background(), msg)
	})
}

func TestHandleMessage_PingQuitReconnectRestart_NoopWithoutWsClient(t *testing.T) {
	c := &Client{PluginName: "alpamon-test-plugin"}
	for _, q := range []string{"ping", "quit", "reconnect", "restart"} {
		msg, _ := json.Marshal(map[string]string{"query": q})
		assert.NotPanics(t, func() {
			c.HandleMessage(context.Background(), msg)
		})
	}
}

func TestNew_ReceiverAlwaysConstructed(t *testing.T) {
	c := New(nil, nil, nil, "alpamon-test-plugin", nil)
	assert.NotNil(t, c)
	assert.Nil(t, c.WsClient)
	assert.NotNil(t, c.Receiver)
	assert.Equal(t, "alpamon-test-plugin", c.PluginName)
	assert.Nil(t, c.OnReconfigure)
}

// TestEnqueueConfigUpdate_LastWriteWins exercises the bounded
// dispatch path. The worker is started lazily on the first call;
// once that worker exits (we pass an already-cancelled context),
// the channel saturates and subsequent enqueues replace each other
// in-place — only the most recent pending ID should survive.
func TestEnqueueConfigUpdate_LastWriteWins(t *testing.T) {
	c := New(nil, nil, nil, "test", nil)

	// First call starts the worker with an already-cancelled ctx, so
	// the worker exits before draining anything. Subsequent enqueues
	// hit the buffered-of-1 channel directly.
	deadCtx, deadCancel := context.WithCancel(context.Background())
	deadCancel()
	c.enqueueConfigUpdate(deadCtx, "id1")

	live := context.Background()
	c.enqueueConfigUpdate(live, "id2")
	c.enqueueConfigUpdate(live, "id3")

	select {
	case got := <-c.configUpdateCh:
		assert.Equal(t, "id3", got, "expected last-write-wins to retain id3")
	default:
		t.Fatal("configUpdateCh empty; expected last enqueued ID to remain")
	}
}

func TestHandleMessage_ReconnectAsksTheLoopInsteadOfActing(t *testing.T) {
	// The loop reapplies the read limit after a reconnect, so only the loop may reconnect.
	// A zero WebsocketClient is enough: the reconnect case no longer touches it.
	c := &Client{PluginName: "alpamon-test-plugin", WsClient: &runner.WebsocketClient{}}
	msg, err := json.Marshal(map[string]string{"query": "reconnect"})
	require.NoError(t, err)

	outcome := c.handleMessage(context.Background(), msg)

	assert.Equal(t, outcomeReconnect, outcome)
}

func TestHandleMessage_ReconnectWithoutWsClientDoesNotAskForReconnect(t *testing.T) {
	// The nil guard sits ahead of the query switch; that contract does not change.
	c := &Client{PluginName: "alpamon-test-plugin"}
	msg, err := json.Marshal(map[string]string{"query": "reconnect"})
	require.NoError(t, err)

	outcome := c.handleMessage(context.Background(), msg)

	assert.Equal(t, outcomeContinue, outcome)
}

func TestHandleMessage_QuitDoesNotAskForReconnect(t *testing.T) {
	c := &Client{
		PluginName: "alpamon-test-plugin",
		WsClient: &runner.WebsocketClient{
			ShutDownChan: make(chan struct{}),
			RestartChan:  make(chan struct{}),
		},
	}
	msg, err := json.Marshal(map[string]string{"query": "quit"})
	require.NoError(t, err)

	outcome := c.handleMessage(context.Background(), msg)

	assert.Equal(t, outcomeContinue, outcome)
}

// reconnectPeerServer upgrades every connection, immediately sends a
// "reconnect" frame, and records when each connection was accepted so the
// test can measure the gap between successive peer-requested reconnects.
//
// runner.peerReconnectMinInterval is unexported, so this test runs at the
// real 5s pacing instead of a shrunk one.
type reconnectPeerServer struct {
	url string

	mu          sync.Mutex
	connectedAt []time.Time
}

func newReconnectPeerServer(t *testing.T) *reconnectPeerServer {
	t.Helper()
	s := &reconnectPeerServer{}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()

		s.mu.Lock()
		s.connectedAt = append(s.connectedAt, time.Now())
		s.mu.Unlock()

		c.SetCloseHandler(func(code int, text string) error {
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(time.Second))
			return nil
		})

		_ = c.WriteJSON(map[string]string{"query": "reconnect", "reason": "test"})

		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(ts.Close)

	s.url = strings.Replace(ts.URL, "http", "ws", 1)
	return s
}

func (s *reconnectPeerServer) connections() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Time, len(s.connectedAt))
	copy(out, s.connectedAt)
	return out
}

func TestRunForever_PacesRepeatedPeerReconnectRequests(t *testing.T) {
	s := newReconnectPeerServer(t)
	origWSPath := config.GlobalSettings.WSPath
	config.GlobalSettings.WSPath = s.url
	t.Cleanup(func() { config.GlobalSettings.WSPath = origWSPath })

	c := &Client{WsClient: runner.NewWebsocketClient(nil, nil, nil)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.RunForever(ctx)
	}()

	require.Eventually(t, func() bool {
		return len(s.connections()) >= 3
	}, 15*time.Second, 20*time.Millisecond, "the read loop did not reconnect at least three times")

	cancel()
	<-done

	// The first peer-requested reconnect is never paced, so the gap to measure is
	// the one after it.
	conns := s.connections()
	require.GreaterOrEqual(t, len(conns), 3)
	// The pacing timer starts when the reconnect is requested, but the server only
	// sees when each dial landed, so a slower dial before the gap shortens it.
	const dialJitter = 50 * time.Millisecond
	gap := conns[2].Sub(conns[1])
	require.GreaterOrEqual(t, gap, 5*time.Second-dialJitter, "the second reconnect came in under peerReconnectMinInterval after the first")
}
