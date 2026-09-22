package pluginclient

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMessage_RejectsEmptyAndOversized(t *testing.T) {
	c := &Client{}

	for _, size := range []int{0, MaxMessageSize + 1} {
		assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), make([]byte, size)))
	}
}

func TestHandleMessage_RejectsUnknownQuery(t *testing.T) {
	called := false
	c := &Client{
		OnReconfigure: func(_ []byte) { called = true },
	}
	for _, q := range []string{"", "SELECT * FROM users", "rm -rf /", "../../etc/passwd"} {
		msg, _ := json.Marshal(map[string]string{"query": q})
		assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), msg))
	}
	assert.False(t, called, "OnReconfigure must not fire for unknown queries")
}

func TestHandleMessage_RejectsMalformedJSON(t *testing.T) {
	c := &Client{}
	for _, payload := range [][]byte{[]byte("{not json"), []byte(`{"query": 42}`)} {
		assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), payload))
	}
}

func TestHandleMessage_ConfigUpdated_RejectsMissingID(t *testing.T) {
	c := &Client{}
	msg, _ := json.Marshal(map[string]string{
		"query":            "config_updated",
		"plugin_config_id": "",
	})
	assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), msg))
}

func TestHandleMessage_ConfigUpdated_RejectsWhenReceiverNil(t *testing.T) {
	c := &Client{Receiver: nil}
	msg, _ := json.Marshal(map[string]string{
		"query":            "config_updated",
		"plugin_config_id": "abc-123",
	})
	assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), msg))
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
	assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), msg))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, string(msg), string(seenMsg))
}

func TestHandleMessage_LegacyReconfigure_NoopWithoutCallback(t *testing.T) {
	c := &Client{} // OnReconfigure nil
	msg, _ := json.Marshal(map[string]string{"query": "reconfigure"})
	assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), msg))
}

func TestHandleMessage_PingQuitReconnectRestart_NoopWithoutWsClient(t *testing.T) {
	c := &Client{PluginName: "alpamon-test-plugin"}
	for _, q := range []string{"ping", "quit", "reconnect", "restart"} {
		msg, _ := json.Marshal(map[string]string{"query": q})
		assert.Equal(t, outcomeContinue, c.handleMessage(context.Background(), msg))
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

// TestRunForever_TakesThePacedPathOnRepeatedPeerReconnectRequests checks only
// that the loop takes the paced path: the runner package's own test already
// measures the pacing interval, and runner.peerReconnectMinInterval is
// unexported so this package cannot shrink it to check the interval cheaply.
func TestRunForever_TakesThePacedPathOnRepeatedPeerReconnectRequests(t *testing.T) {
	s := testutil.NewReconnectPeerServer(t)
	origWSPath := config.GlobalSettings.WSPath
	config.GlobalSettings.WSPath = s.URL
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
		return len(s.Connections()) >= 2
	}, 15*time.Second, 20*time.Millisecond, "the read loop did not reconnect at least twice")

	assert.Never(t, func() bool {
		return len(s.Connections()) >= 3
	}, time.Second, 10*time.Millisecond, "a third connection arrived before the pacing interval, so the loop skipped the paced wait")

	cancel()
	<-done
}
