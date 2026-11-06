package runner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebsocketClientWriteJSON_ReturnsErrorWhenThereIsNoConnection(t *testing.T) {
	// A zero-value client used to panic inside gorilla's beginMessage.
	wc := &WebsocketClient{}

	err := wc.WriteJSON(map[string]string{"query": "ping"})

	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestWebsocketClientSetReadLimit_WithoutAConnectionCapsTheNextOne(t *testing.T) {
	const limit = 64
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		_ = c.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("x", limit+1)))
		_ = readUntilError(c)
	})
	useWSPath(t, url)
	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	require.NotPanics(t, func() { wc.SetReadLimit(limit) })

	require.NoError(t, wc.Connect(context.Background()))
	t.Cleanup(wc.Close)
	_, _, err := wc.ReadMessage()

	assert.ErrorIs(t, err, websocket.ErrReadLimit)
}

func TestWebsocketClientSetReadDeadline_ReturnsErrorWhenThereIsNoConnection(t *testing.T) {
	wc := &WebsocketClient{}

	err := wc.SetReadDeadline(time.Now().Add(time.Second))

	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestSendPingQuery_WritesThePingQueryAsOneTextFrame(t *testing.T) {
	type frame struct {
		kind int
		data []byte
	}
	received := make(chan frame, 1)
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		kind, data, err := c.ReadMessage()
		if err == nil {
			received <- frame{kind, data}
		}
		_ = readUntilError(c)
	})
	useWSPath(t, url)
	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	require.NoError(t, wc.Connect(context.Background()))
	t.Cleanup(wc.Close)

	err := wc.SendPingQuery()

	require.NoError(t, err)
	select {
	case got := <-received:
		assert.Equal(t, websocket.TextMessage, got.kind)
		assert.JSONEq(t, `{"query":"ping"}`, string(got.data))
	case <-time.After(5 * time.Second):
		t.Fatal("the server never received the ping query")
	}
}

func TestSendPingQuery_ReturnsErrorWhenThereIsNoConnection(t *testing.T) {
	wc := &WebsocketClient{}

	err := wc.SendPingQuery()

	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestSendPingQuery_ReturnsErrCloseSentAfterTheConnectionIsClosed(t *testing.T) {
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) { _ = readUntilError(c) })
	useWSPath(t, url)
	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	require.NoError(t, wc.Connect(context.Background()))
	wc.Close()

	err := wc.SendPingQuery()

	assert.ErrorIs(t, err, websocket.ErrCloseSent)
}
