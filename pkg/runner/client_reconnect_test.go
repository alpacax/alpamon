package runner

import (
	"context"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil"
	"github.com/alpacax/alpamon/v2/pkg/config"
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
	assert.Same(t, conn, wc.conn(), "CloseAndReconnect dialled a new connection after the context was cancelled")
}

func TestCloseAndReconnectOnRequest_FirstRequestIsNotDelayed(t *testing.T) {
	s := newCloseReplyServer(t)
	conn, _ := dialTracked(t, s.url)
	wc := &WebsocketClient{Conn: conn, connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}

	original := config.GlobalSettings.WSPath
	config.GlobalSettings.WSPath = s.url
	t.Cleanup(func() { config.GlobalSettings.WSPath = original })

	start := time.Now()
	err := wc.CloseAndReconnectOnRequest(context.Background())
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, peerReconnectMinInterval, "the first peer-requested reconnect waited as if it were not the first")
	assert.False(t, wc.lastPeerReconnect.IsZero(), "lastPeerReconnect was not recorded")
}

func TestCloseAndReconnectOnRequest_SecondRequestRightAfterWaits(t *testing.T) {
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)
	// connectBackoff is set so a regression that skips the wait fails on the assertion below
	// instead of panicking inside Connect and taking the whole package down with it.
	wc := &WebsocketClient{Conn: conn, lastPeerReconnect: time.Now(), connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := wc.CloseAndReconnectOnRequest(ctx)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, tracked.closed.Load(), "the second request dialled instead of waiting")
}

func TestRunForever_PacesRepeatedPeerReconnectRequests(t *testing.T) {
	// Shrunk so the test does not wait out real pacing.
	origInterval := peerReconnectMinInterval
	peerReconnectMinInterval = 200 * time.Millisecond
	t.Cleanup(func() { peerReconnectMinInterval = origInterval })

	s := testutil.NewReconnectPeerServer(t)
	origWSPath := config.GlobalSettings.WSPath
	config.GlobalSettings.WSPath = s.URL
	t.Cleanup(func() { config.GlobalSettings.WSPath = origWSPath })

	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		wc.RunForever(ctx)
	}()

	require.Eventually(t, func() bool {
		return len(s.Connections()) >= 3
	}, 5*time.Second, 10*time.Millisecond, "the read loop did not reconnect at least three times")

	cancel()
	<-done

	// The first peer-requested reconnect is never paced, so the gap to measure is the one after it.
	// An unpaced gap falls under 1% of the interval, so a half-interval margin still fails on a regression.
	closes := s.Closes()
	require.GreaterOrEqual(t, len(closes), 2, "expected at least two close frames from paced reconnects")
	margin := peerReconnectMinInterval / 2
	gap := closes[1].Sub(closes[0])
	require.GreaterOrEqual(t, gap, peerReconnectMinInterval-margin, "the second reconnect came in under peerReconnectMinInterval after the first")
}
