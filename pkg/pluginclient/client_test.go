package pluginclient

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
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
