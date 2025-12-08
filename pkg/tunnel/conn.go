package tunnel

import (
	"net"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn wraps a WebSocket connection to implement net.Conn interface.
// This adapter is required for smux which expects net.Conn.
type WebSocketConn struct {
	conn       *websocket.Conn
	readBuffer []byte
}

// NewWebSocketConn creates a new WebSocket to net.Conn adapter.
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

// LocalAddr returns the local network address.
func (w *WebSocketConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (w *WebSocketConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

// SetDeadline sets read and write deadlines.
func (w *WebSocketConn) SetDeadline(t time.Time) error {
	if err := w.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return w.conn.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (w *WebSocketConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (w *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// Ensure WebSocketConn implements net.Conn
var _ net.Conn = (*WebSocketConn)(nil)
