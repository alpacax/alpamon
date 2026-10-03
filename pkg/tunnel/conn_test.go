package tunnel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConnPair(t testing.TB) (*WebSocketConn, *websocket.Conn) {
	t.Helper()
	serverConns := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConns <- c
	}))
	t.Cleanup(srv.Close)

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server := <-serverConns
	t.Cleanup(func() { _ = server.Close() })
	return NewWebSocketConn(client), server
}

func TestWebSocketConnReadSplitsMessageLargerThanBuffer(t *testing.T) {
	wc, server := newConnPair(t)
	msg := []byte("0123456789abcdefghij")
	require.NoError(t, server.WriteMessage(websocket.BinaryMessage, msg))

	var got []byte
	for len(got) < len(msg) {
		buf := make([]byte, 7)
		n, err := wc.Read(buf)
		require.NoError(t, err)
		require.LessOrEqual(t, n, 7)
		got = append(got, buf[:n]...)
	}

	assert.Equal(t, msg, got)
}

func TestWebSocketConnReadReturnsSmallMessageInOneRead(t *testing.T) {
	wc, server := newConnPair(t)
	require.NoError(t, server.WriteMessage(websocket.BinaryMessage, []byte("hi")))

	buf := make([]byte, 64)
	n, err := wc.Read(buf)

	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), buf[:n])
}

func TestWebSocketConnReadSkipsEmptyMessage(t *testing.T) {
	wc, server := newConnPair(t)
	require.NoError(t, server.WriteMessage(websocket.BinaryMessage, nil))
	require.NoError(t, server.WriteMessage(websocket.BinaryMessage, []byte("data")))

	buf := make([]byte, 64)
	n, err := wc.Read(buf)

	require.NoError(t, err)
	assert.Equal(t, []byte("data"), buf[:n])
}

func TestWebSocketConnReadKeepsMessageBoundariesAcrossMessages(t *testing.T) {
	wc, server := newConnPair(t)
	for _, m := range []string{"first", "second", "third"} {
		require.NoError(t, server.WriteMessage(websocket.BinaryMessage, []byte(m)))
	}

	got := make([]byte, len("firstsecondthird"))
	_, err := io.ReadFull(wc, got)

	require.NoError(t, err)
	assert.Equal(t, "firstsecondthird", string(got))
}

func TestWebSocketConnReadReturnsCloseErrorAfterServerClose(t *testing.T) {
	wc, server := newConnPair(t)
	require.NoError(t, server.WriteMessage(websocket.BinaryMessage, []byte("ab")))
	require.NoError(t, server.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"), time.Now().Add(time.Second)))

	buf := make([]byte, 1)
	_, err := io.ReadFull(wc, buf)
	require.NoError(t, err)
	_, err = wc.Read(buf)
	require.NoError(t, err)
	_, err = wc.Read(buf)

	var ce *websocket.CloseError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, websocket.CloseNormalClosure, ce.Code)
}

func TestWebSocketConnReadReturnsErrorAfterLocalClose(t *testing.T) {
	wc, _ := newConnPair(t)
	require.NoError(t, wc.Close())

	_, err := wc.Read(make([]byte, 8))

	assert.Error(t, err)
}

func BenchmarkWebSocketConnRead(b *testing.B) {
	const payload = 32768
	wc, server := newConnPair(b)
	msg := make([]byte, 8+payload)
	done := make(chan struct{})
	b.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if err := server.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				return
			}
		}
	}()
	hdr := make([]byte, 8)
	body := make([]byte, payload)

	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := io.ReadFull(wc, hdr); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(wc, body); err != nil {
			b.Fatal(err)
		}
	}
}
