package testutil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ReconnectPeerServer upgrades every connection, immediately sends a
// "reconnect" frame, and records when each connection was accepted and when
// each connection's close frame arrived, so a test can measure the gap
// between successive peer-requested reconnects without the dial and drain.
type ReconnectPeerServer struct {
	URL string

	mu          sync.Mutex
	connectedAt []time.Time
	closedAt    []time.Time
}

// NewReconnectPeerServer starts the server and registers its cleanup on t.
func NewReconnectPeerServer(t *testing.T) *ReconnectPeerServer {
	t.Helper()
	s := &ReconnectPeerServer{}
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
			s.mu.Lock()
			s.closedAt = append(s.closedAt, time.Now())
			s.mu.Unlock()
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(time.Second))
			return nil
		})

		_ = c.WriteJSON(map[string]string{"query": "reconnect", "reason": "test"})

		// The close handler only fires while a read is in flight, so this loop
		// must keep reading until the client's close frame arrives.
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(ts.Close)

	s.URL = strings.Replace(ts.URL, "http", "ws", 1)
	return s
}

// Connections returns the time each connection was accepted, in order.
func (s *ReconnectPeerServer) Connections() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Time, len(s.connectedAt))
	copy(out, s.connectedAt)
	return out
}

// Closes returns the time each connection's close frame arrived, in order.
func (s *ReconnectPeerServer) Closes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Time, len(s.closedAt))
	copy(out, s.closedAt)
	return out
}
