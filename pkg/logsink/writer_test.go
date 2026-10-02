package logsink

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sockCounter atomic.Uint64

// shortSocketPath returns a UDS path short enough to fit in the
// 104-byte sun_path limit on darwin. t.TempDir() can produce paths that
// exceed this limit and cause "bind: invalid argument" on macOS, so on
// darwin we anchor under /tmp; elsewhere os.TempDir() is fine.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "lsk")
	require.NoError(t, err, "mkdtemp")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("%d.s", sockCounter.Add(1)))
}

// startTestServer spins up a Unix-domain listener at a temporary path and
// returns the path along with a channel of received frames (length-prefix
// stripped). Frames are delivered in arrival order across all connections.
func startTestServer(t *testing.T) (path string, frames <-chan []byte, stop func()) {
	t.Helper()
	path = shortSocketPath(t)

	ln, err := net.Listen("unix", path)
	require.NoError(t, err, "listen")

	ch := make(chan []byte, 16)
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)

	acceptDone := make(chan struct{})
	wg.Go(func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Go(func() {
				var hdr [4]byte
				for {
					if _, err := io.ReadFull(conn, hdr[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(hdr[:])
					body := make([]byte, n)
					if _, err := io.ReadFull(conn, body); err != nil {
						return
					}
					ch <- body
				}
			})
		}
	})

	stop = func() {
		_ = ln.Close()
		// Drain the accept loop first: an in-flight Accept can append to
		// conns after stop() has already closed them, stranding its reader.
		<-acceptDone
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
		close(ch)
	}
	return path, ch, stop
}

// newTestWriter builds a Writer pointing at an arbitrary socket path
// (bypassing SocketPath() so tests don't depend on RunDir()).
func newTestWriter(path, program string, handlers map[string]int) *Writer {
	h := make(map[string]int, len(handlers))
	maps.Copy(h, handlers)
	w := &Writer{
		program:  program,
		pid:      4242,
		handlers: h,
		path:     path,
	}
	w.conn, _ = net.DialTimeout("unix", path, dialTimeout)
	return w
}

func zerologLine(t *testing.T, level, caller, msg string) []byte {
	t.Helper()
	b, err := json.Marshal(logger.ZerologEntry{
		Level:   level,
		Time:    "2026-05-02T00:00:00Z",
		Caller:  caller,
		Message: msg,
	})
	require.NoError(t, err, "marshal entry")
	return b
}

func recvFrame(t *testing.T, frames <-chan []byte) []byte {
	t.Helper()
	select {
	case f := <-frames:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for frame")
		return nil
	}
}

func expectNoFrame(t *testing.T, frames <-chan []byte) {
	t.Helper()
	select {
	case f := <-frames:
		require.Fail(t, "unexpected frame: "+string(f))
	case <-time.After(150 * time.Millisecond):
	}
}

func TestWriter_ForwardsRecordWhenHandlerMatches(t *testing.T) {
	path, frames, stop := startTestServer(t)
	defer stop()

	w := newTestWriter(path, "myplugin", map[string]int{"plugin.go": 30})
	defer func() { _ = w.Close() }()

	n, err := w.Write(zerologLine(t, "error", "github.com/x/y/plugin.go:42", "boom"))
	require.NoError(t, err, "write")
	require.NotZero(t, n, "expected non-zero return")

	body := recvFrame(t, frames)
	var got logger.LogRecord
	require.NoError(t, json.Unmarshal(body, &got), "unmarshal record")
	assert.Equal(t, "myplugin", got.Program)
	assert.Equal(t, 40, got.Level)
	assert.Equal(t, 42, got.Lineno)
	assert.Equal(t, 4242, got.PID)
	assert.Equal(t, "boom", got.Msg)
}

func TestWriter_FiltersUnlistedFile(t *testing.T) {
	path, frames, stop := startTestServer(t)
	defer stop()

	w := newTestWriter(path, "myplugin", map[string]int{"plugin.go": 30})
	defer func() { _ = w.Close() }()

	_, _ = w.Write(zerologLine(t, "error", "other.go:10", "ignored"))
	expectNoFrame(t, frames)
}

func TestWriter_FiltersBelowThreshold(t *testing.T) {
	path, frames, stop := startTestServer(t)
	defer stop()

	w := newTestWriter(path, "myplugin", map[string]int{"plugin.go": 30})
	defer func() { _ = w.Close() }()

	// info=20, threshold=30
	_, _ = w.Write(zerologLine(t, "info", "plugin.go:1", "below"))
	expectNoFrame(t, frames)

	// warn=30, exactly at threshold — passes
	_, _ = w.Write(zerologLine(t, "warn", "plugin.go:1", "at"))
	_ = recvFrame(t, frames)
}

func TestWriter_DropsOversizedRecord(t *testing.T) {
	path, frames, stop := startTestServer(t)
	defer stop()

	w := newTestWriter(path, "p", map[string]int{"plugin.go": 10})
	defer func() { _ = w.Close() }()

	huge := strings.Repeat("x", logger.MaxFrameSize)
	_, _ = w.Write(zerologLine(t, "error", "plugin.go:1", huge))
	expectNoFrame(t, frames)
}

func TestWriter_SilentOnInvalidJSON(t *testing.T) {
	path, _, stop := startTestServer(t)
	defer stop()

	w := newTestWriter(path, "p", map[string]int{"plugin.go": 10})
	defer func() { _ = w.Close() }()

	garbage := []byte("not json")
	n, err := w.Write(garbage)
	require.NoError(t, err, "Write(invalid)")
	require.Equal(t, len(garbage), n, "Write(invalid) byte count")
}

func TestWriter_HandlersMapIsCopied(t *testing.T) {
	path, frames, stop := startTestServer(t)
	defer stop()

	handlers := map[string]int{"plugin.go": 30}
	w := New("p", handlers)
	defer func() { _ = w.Close() }()
	w.path = path
	// Mutate the caller's map after construction. If New() didn't copy,
	// the writer's filter would change too.
	handlers["plugin.go"] = 50
	delete(handlers, "plugin.go")

	w.conn, _ = net.DialTimeout("unix", path, dialTimeout)
	_, _ = w.Write(zerologLine(t, "error", "plugin.go:1", "still-forwarded"))
	_ = recvFrame(t, frames)
}

func TestWriter_ReconnectsAfterServerRestart(t *testing.T) {
	path, frames, stop := startTestServer(t)

	w := newTestWriter(path, "p", map[string]int{"plugin.go": 10})
	defer func() { _ = w.Close() }()

	_, _ = w.Write(zerologLine(t, "error", "plugin.go:1", "first"))
	_ = recvFrame(t, frames)

	// Drop the server. Force the writer to drop its conn too: a write
	// to a server-closed peer doesn't reliably fail-fast on every
	// platform (notably Windows), so we can't rely on Write() alone to
	// trigger reconnect. We're testing tryReconnect's path here, not
	// peer-disconnect detection.
	stop()
	w.mu.Lock()
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
	w.lastFail = time.Time{}
	// Bring a fresh server up at a new path; tempdirs differ per call.
	path2, frames2, stop2 := startTestServer(t)
	defer stop2()
	w.path = path2
	w.mu.Unlock()

	_, _ = w.Write(zerologLine(t, "error", "plugin.go:1", "after-restart"))
	body := recvFrame(t, frames2)
	var got logger.LogRecord
	require.NoError(t, json.Unmarshal(body, &got), "unmarshal")
	assert.Equal(t, "after-restart", got.Msg)
}

func TestWriter_FrameFormat(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	require.NoError(t, err, "listen")
	defer func() { _ = ln.Close() }()

	w := newTestWriter(path, "p", map[string]int{"plugin.go": 10})
	defer func() { _ = w.Close() }()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		connCh <- c
	}()

	_, _ = w.Write(zerologLine(t, "error", "plugin.go:7", "hi"))

	conn := <-connCh
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var hdr [4]byte
	_, err = io.ReadFull(conn, hdr[:])
	require.NoError(t, err, "read header")
	length := binary.BigEndian.Uint32(hdr[:])
	require.NotZero(t, length, "length out of range")
	require.LessOrEqual(t, length, uint32(logger.MaxFrameSize), "length out of range")
	body := make([]byte, length)
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err, "read body")
	var rec logger.LogRecord
	require.NoError(t, json.Unmarshal(body, &rec), "unmarshal")
	assert.Equal(t, 7, rec.Lineno, "unexpected record: %+v", rec)
	assert.Equal(t, "hi", rec.Msg, "unexpected record: %+v", rec)
}
