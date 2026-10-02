package tunnel

import (
	"io"
	"sync"

	"github.com/gorilla/websocket"
)

// WebSocketConn wraps a WebSocket connection to implement io.ReadWriteCloser.
// This adapter is required for smux which expects io.ReadWriteCloser.
type WebSocketConn struct {
	conn    *websocket.Conn
	reader  io.Reader
	writeMu sync.Mutex
}

// NewWebSocketConn creates a new WebSocket to io.ReadWriteCloser adapter.
func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{conn: conn}
}

// Read reads data from the current WebSocket message and moves to the next one at its end.
// It is meant for a single reader goroutine, which is how smux uses it.
func (w *WebSocketConn) Read(b []byte) (int, error) {
	for {
		if w.reader == nil {
			_, r, err := w.conn.NextReader()
			if err != nil {
				return 0, err
			}
			w.reader = r
		}
		n, err := w.reader.Read(b)
		if err == io.EOF {
			w.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

// Write writes data to the WebSocket connection as a binary message.
// The write is protected by a mutex to ensure thread safety for concurrent calls from multiple smux streams.
func (w *WebSocketConn) Write(b []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	err := w.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes the WebSocket connection.
func (w *WebSocketConn) Close() error {
	return w.conn.Close()
}

var _ io.ReadWriteCloser = (*WebSocketConn)(nil)
