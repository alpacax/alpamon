package runner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/UserExistsError/conpty"
	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsPtyCancelBeforeStart(t *testing.T) {
	var registry commandCancellations
	ctx, open := registry.register(context.Background(), "openpty-id")
	ctx = context.WithValue(ctx, cancellationRegistryKey{}, &registry)
	pc := NewPtyClient(protocol.CommandData{SessionID: "pending"}, nil, NewTerminalManager(nil))
	pc.TrackCommand(ctx, "openpty-id")
	registry.finish("openpty-id", open)
	require.Len(t, registry.active["openpty-id"], 1)
	registry.cancel("openpty-id")
	pc.RunPtyBackground()
	assert.NotContains(t, registry.active, "openpty-id")
	require.NotNil(t, pc.cancelState)
	cancelled, survivors := pc.cancelState.Finish()
	assert.True(t, cancelled)
	assert.Empty(t, survivors)
	assert.Nil(t, pc.cpty, "cancel before start must not launch a shell")
}

func TestWindowsPtyCancelClosesTerminal(t *testing.T) {
	if !conpty.IsConPtyAvailable() {
		t.Skip("ConPTY is unavailable")
	}
	closed := make(chan error, 1)
	output := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			closed <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte("for /L %i in (1,1,100000000) do @echo sustained-output\r\n")); err != nil {
			closed <- err
			return
		}
		bytesRead := 0
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				closed <- err
				return
			}
			bytesRead += len(data)
			if bytesRead >= 4*bufferSize {
				select {
				case output <- struct{}{}:
				default:
				}
			}
		}
	}))
	t.Cleanup(server.Close)
	manager := NewTerminalManager(nil)
	wc := &WebsocketClient{}
	ctx, open := wc.cancellations.register(context.Background(), "openpty-id")
	ctx = context.WithValue(ctx, cancellationRegistryKey{}, &wc.cancellations)
	pc := NewPtyClient(protocol.CommandData{SessionID: "running", URL: "ws" + strings.TrimPrefix(server.URL, "http"), Shell: "cmd.exe", Rows: 24, Cols: 80}, nil, manager)
	pc.TrackCommand(ctx, "openpty-id")
	wc.cancellations.finish("openpty-id", open)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pc.RunPtyBackground()
	}()
	t.Cleanup(func() {
		wc.cancellations.cancel("openpty-id")
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("terminal worker did not exit")
		}
	})
	require.Eventually(t, func() bool { return manager.Get(pc.sessionID) != nil }, 5*time.Second, 20*time.Millisecond)
	// ConPTY still owns the shell handle here, so its PID cannot be reused.
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pc.cpty.Pid()))
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(handle) }()
	select {
	case <-output:
	case <-time.After(5 * time.Second):
		t.Fatal("terminal did not produce output")
	}
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"openpty-id"}}`))
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not stop the terminal worker")
	}
	wait, err := windows.WaitForSingleObject(handle, 2000)
	require.NoError(t, err)
	assert.Equal(t, uint32(windows.WAIT_OBJECT_0), wait, "ConPTY shell survived cancellation")
	assert.Nil(t, manager.Get(pc.sessionID))
	wc.cancellations.mu.Lock()
	assert.NotContains(t, wc.cancellations.active, "openpty-id")
	wc.cancellations.mu.Unlock()
	cancelled, survivors := pc.cancelState.Finish()
	assert.True(t, cancelled)
	assert.Empty(t, survivors)
	select {
	case err := <-closed:
		var closeErr *websocket.CloseError
		require.ErrorAs(t, err, &closeErr)
		assert.Equal(t, websocket.CloseNormalClosure, closeErr.Code)
	case <-time.After(time.Second):
		t.Fatal("terminal channel did not close")
	}
}

func TestWindowsPtyOutputDrainsAfterCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader, writer := io.Pipe()
		defer func() { _ = reader.Close(); _ = writer.Close() }()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		pc := &PtyClient{ptyToWs: make(chan []byte)}
		done := make(chan struct{})
		go func() {
			defer close(done)
			pc.readFromPty(ctx, cancel, reader)
		}()
		written := make(chan error, 1)
		go func() {
			_, err := io.WriteString(writer, strings.Repeat("x", 2*bufferSize))
			written <- err
		}()
		select {
		case err := <-written:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("output reader stopped before ConPTY closed")
		}
		select {
		case <-done:
			t.Fatal("output reader exited before EOF")
		default:
		}
		require.NoError(t, writer.Close())
		<-done
	})
}
