//go:build !windows

package runner

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdmittedCommandCannotStartAfterPause(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	cr := &CommandRunner{command: protocol.Command{ID: "command-start", WorkSessionID: wsID}, workSessions: r}
	ctx, release, err := cr.admitWorkSession(t.Context())
	require.NoError(t, err)
	defer release()
	guard := common.ProcessStartGuardFromContext(ctx)
	require.NotNil(t, guard)
	(&ControlClient{workSessions: r}).HandleMessage(pauseFrame(t, 1))
	finish, err := guard()
	if finish != nil {
		finish()
	}
	assert.ErrorIs(t, err, errWorkSessionPaused)
}

func TestAdmittedCommandRechecksOriginalAttributionAtStartup(t *testing.T) {
	for _, name := range []string{"new revision", "request expiry"} {
		t.Run(name, func(t *testing.T) {
			server := &fakeControlServer{}
			server.set(workSessionActive, 0)
			r := newTestRegistry(server)
			now := wsNow
			r.now = func() time.Time { return now }
			expiresAt := now.Add(time.Minute)
			cr := &CommandRunner{command: protocol.Command{
				ID: "command-start", WorkSessionID: wsID, WorkSessionExpiresAt: expiresAt.Format(time.RFC3339),
			}, workSessions: r}
			ctx, release, err := cr.admitWorkSession(t.Context())
			require.NoError(t, err)
			defer release()
			guard := common.ProcessStartGuardFromContext(ctx)
			require.NotNil(t, guard)

			want := errWorkSessionExpired
			if name == "new revision" {
				control := &ControlClient{workSessions: r}
				control.HandleMessage(pauseFrame(t, 1))
				control.HandleMessage(resumeFrame(t, 2))
				want = errWorkSessionStale
			} else {
				now = expiresAt
			}

			finish, err := guard()
			if finish != nil {
				finish()
			}
			assert.ErrorIs(t, err, want)
		})
	}
}

func TestPendingWebshStartIsFencedAfterPause(t *testing.T) {
	control := &fakeControlServer{}
	control.set(workSessionActive, 0)
	r := newTestRegistry(control)
	cc := &ControlClient{workSessions: r}
	release, err := r.admit(t.Context(), attribution(0), "open-pending")
	require.NoError(t, err)
	defer release()
	connecting, allowHandshake := make(chan struct{}), make(chan struct{})
	finishHandshake := sync.OnceFunc(func() { close(allowHandshake) })
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(connecting)
		<-allowHandshake
		conn, err := upgrader.Upgrade(w, req, nil)
		if err == nil {
			defer func() { _ = conn.Close() }()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(s.Close)
	t.Cleanup(finishHandshake)
	previousURL := config.GlobalSettings.ServerURL
	config.GlobalSettings.ServerURL = s.URL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = previousURL })
	pc := NewPtyClient(protocol.CommandData{
		URL: strings.Replace(s.URL, "http", "ws", 1), SessionID: "pending-websh", Shell: "/bin/sh", Rows: 24, Cols: 80,
	}, nil, NewTerminalManager(nil))
	pc.TrackCommand(withWorkSession(t.Context(), &workSessionBinding{registry: r, attribution: attribution(0)}), "open-pending")
	t.Cleanup(pc.close)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- pc.initializePtySession(ctx) }()
	select {
	case <-connecting:
	case <-time.After(3 * time.Second):
		t.Fatal("Websh did not begin connecting")
	}
	cc.HandleMessage(pauseFrame(t, 1))
	finishHandshake()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, errWorkSessionPaused)
	case <-time.After(3 * time.Second):
		t.Fatal("Websh startup did not finish after its handshake")
	}
	require.NotNil(t, pc.cmd)
	assert.Nil(t, pc.cmd.Process, "Pause must fence the actual shell Start after a pending Websh connection")
}

func TestTerminalQueuedInputCannotCrossPauseAndResume(t *testing.T) {
	control := &fakeControlServer{}
	control.set(workSessionActive, 0)
	r := newTestRegistry(control)
	cc := &ControlClient{workSessions: r}
	release, err := r.admit(t.Context(), attribution(0), "open-queued")
	require.NoError(t, err)
	defer release()
	peer := make(chan *websocket.Conn, 1)
	s := newWshServerWith(t, func(_ int, conn *websocket.Conn) { peer <- conn })
	pc := newTestPtyClient(t, s)
	pc.TrackCommand(withWorkSession(t.Context(), &workSessionBinding{registry: r, attribution: attribution(0)}), "open-queued")
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	pc.ptmx = writer
	t.Cleanup(func() { _ = reader.Close() })
	t.Cleanup(pc.close)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	readDone, writeDone := make(chan struct{}), make(chan struct{})
	pausedInputRead := make(chan struct{})
	pc.conn.SetPingHandler(func(string) error { close(pausedInputRead); return nil })
	go func() { defer close(readDone); pc.readFromWebsocket(ctx, cancel, make(chan struct{}, 1)) }()
	remote := <-peer
	t.Cleanup(func() { _ = remote.Close() })
	require.NoError(t, remote.WriteMessage(websocket.BinaryMessage, []byte("before-pause")))
	require.Eventually(t, func() bool { return len(pc.wsToPty) == 1 }, 3*time.Second, time.Millisecond)
	cc.HandleMessage(pauseFrame(t, 1))
	require.NoError(t, remote.WriteMessage(websocket.BinaryMessage, []byte("during-pause")))
	require.NoError(t, remote.WriteControl(websocket.PingMessage, []byte("input-read"), time.Now().Add(time.Second)))
	select {
	case <-pausedInputRead:
	case <-time.After(3 * time.Second):
		t.Fatal("Websh did not read the paused input")
	}
	assert.Len(t, pc.wsToPty, 1, "input received while paused must be discarded before it reaches the queue")
	cc.HandleMessage(resumeFrame(t, 2))
	require.NoError(t, remote.WriteMessage(websocket.BinaryMessage, []byte("after-resume\n")))
	go func() { defer close(writeDone); pc.writeToPty(ctx, cancel) }()
	written := make(chan string, 1)
	go func() { data, _ := bufio.NewReader(reader).ReadString('\n'); written <- data }()
	select {
	case data := <-written:
		assert.Equal(t, "after-resume\n", data, "queued input must be invalidated by a Pause, even after Resume")
	case <-time.After(3 * time.Second):
		t.Fatal("resumed terminal did not receive fresh input")
	}
	cancel()
	_ = pc.conn.Close()
	<-readDone
	<-writeDone
}
