package runner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandRequestHandler_ReconnectAsksTheLoopInsteadOfClosing(t *testing.T) {
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)
	wc := &WebsocketClient{Conn: conn}

	outcome := wc.commandRequestHandler([]byte(`{"query":"reconnect","reason":"test"}`))

	require.Equal(t, outcomeReconnect, outcome)
	assert.False(t, tracked.closed.Load(), "the handler closed the connection instead of asking the loop to reconnect")
}

func TestCommandRequestHandler_QuitDoesNotAskForReconnect(t *testing.T) {
	wc := &WebsocketClient{
		RestartChan:  make(chan struct{}),
		ShutDownChan: make(chan struct{}),
	}

	outcome := wc.commandRequestHandler([]byte(`{"query":"quit","reason":"test"}`))

	assert.Equal(t, outcomeContinue, outcome)
}

func TestCommandRequestHandler_EmptyMessageSkipsParsingWithoutLogging(t *testing.T) {
	// json.Unmarshal(nil, ...) errors too, so outcomeContinue alone does not prove the
	// early return fired; only the absent warning separates it from the parse-error path.
	logs := captureLogs(t)
	wc := &WebsocketClient{}

	outcome := wc.commandRequestHandler(nil)

	assert.Equal(t, outcomeContinue, outcome)
	assert.Empty(t, logs.String(), "an empty message should return before ParseMessage ever logs")
}

func TestCloseAndReconnect_DoesNotReconnectAfterContextCancel(t *testing.T) {
	// gracefulShutdown cancels the root context before it calls Close.
	s := newCloseReplyServer(t)
	conn, _ := dialTracked(t, s.url)
	wc := &WebsocketClient{Conn: conn}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := wc.CloseAndReconnect(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Same(t, conn, wc.getConn(), "CloseAndReconnect dialled a new connection after the context was cancelled")
}
