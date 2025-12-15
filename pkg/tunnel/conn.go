package tunnel

import (
	"io"

	"github.com/gorilla/websocket"
)

// WebSocketConn wraps a WebSocket connection to implement io.ReadWriteCloser.
// This adapter is required for smux which expects io.ReadWriteCloser.
type WebSocketConn struct {
	conn       *websocket.Conn
	readBuffer []byte
}

// NewWebSocketConn creates a new WebSocket to io.ReadWriteCloser adapter.
func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{conn: conn}
}

// Read reads data from the WebSocket connection.
// WebSocket messages that are larger than the provided buffer are buffered internally.
func (w *WebSocketConn) Read(b []byte) (int, error) {
	// Return previously buffered data first
	if len(w.readBuffer) > 0 {
		n := copy(b, w.readBuffer)
		w.readBuffer = w.readBuffer[n:]
		return n, nil
	}

	// Read new message
	_, msg, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// Copy to buffer
	n := copy(b, msg)

	// Buffer remaining data if message was larger than buffer
	if n < len(msg) {
		w.readBuffer = msg[n:]
	}

	return n, nil
}

// Write writes data to the WebSocket connection as a binary message.
func (w *WebSocketConn) Write(b []byte) (int, error) {
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
