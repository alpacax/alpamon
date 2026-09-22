package runner

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWebsocketClientWriteJSON_ReturnsErrorWhenThereIsNoConnection(t *testing.T) {
	// A zero-value client used to panic inside gorilla's beginMessage.
	wc := &WebsocketClient{}

	err := wc.WriteJSON(map[string]string{"query": "ping"})

	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestWebsocketClientSetReadLimit_IsANoOpWhenThereIsNoConnection(t *testing.T) {
	wc := &WebsocketClient{}

	assert.NotPanics(t, func() { wc.SetReadLimit(1024) })
}

func TestWebsocketClientSetReadDeadline_ReturnsErrorWhenThereIsNoConnection(t *testing.T) {
	wc := &WebsocketClient{}

	err := wc.SetReadDeadline(time.Now().Add(time.Second))

	assert.ErrorIs(t, err, net.ErrClosed)
}
