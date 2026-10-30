package runner

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/gorilla/websocket"
)

// NewChunkCallback lets runner_test, which imports pkg/executor and so cannot
// live in package runner, drive the real callback.
func NewChunkCallback(cr *CommandRunner) func(ctx context.Context, content string) {
	return cr.newChunkCallback()
}

// StartFakeAlpacon exposes startFakeAlpacon; contents preserves delivery order.
func StartFakeAlpacon(t *testing.T) (cleanup func(), contents func() []string) {
	t.Helper()
	cleanup, mu, bodies := startFakeAlpacon(t)
	contents = func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(*bodies))
		for i, c := range *bodies {
			out[i] = c.content
		}
		return out
	}
	return cleanup, contents
}

// SetDial lets runner_test hand a client an in-memory socket instead of a TCP dial.
func SetDial(
	wc *WebsocketClient,
	dial func(ctx context.Context, url string, header http.Header) (*websocket.Conn, error),
) {
	wc.dial = dial
}

// DialPipe exposes dialPipe to runner_test.
func DialPipe(t *testing.T, serve func(peer net.Conn)) (*websocket.Conn, error) {
	t.Helper()
	return dialPipe(t, nil, serve)
}
