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
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
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
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

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
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				var hdr [4]byte
				for {
					if _, err := io.ReadFull(c, hdr[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(hdr[:])
					body := make([]byte, n)
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					ch <- body
				}
			}(conn)
		}
	})

	stop = func() {
		_ = ln.Close()
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
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
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
		t.Fatalf("unexpected frame: %s", string(f))
	case <-time.After(150 * time.Millisecond):
	}
}

func TestWriter_ForwardsRecordWhenHandlerMatches(t *testing.T) {
	path, frames, stop := startTestServer(t)
	defer stop()

	w := newTestWriter(path, "myplugin", map[string]int{"plugin.go": 30})
	defer func() { _ = w.Close() }()

	n, err := w.Write(zerologLine(t, "error", "github.com/x/y/plugin.go:42", "boom"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected non-zero return, got %d", n)
	}

	body := recvFrame(t, frames)
	var got logger.LogRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if got.Program != "myplugin" {
		t.Errorf("Program = %q, want myplugin", got.Program)
	}
	if got.Level != 40 {
		t.Errorf("Level = %d, want 40", got.Level)
	}
	if got.Lineno != 42 {
		t.Errorf("Lineno = %d, want 42", got.Lineno)
	}
	if got.PID != 4242 {
		t.Errorf("PID = %d, want 4242", got.PID)
	}
	if got.Msg != "boom" {
		t.Errorf("Msg = %q, want boom", got.Msg)
	}
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
	if err != nil || n != len(garbage) {
		t.Fatalf("Write(invalid) = (%d, %v), want (%d, nil)", n, err, len(garbage))
	}
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
	_ = path

	_, _ = w.Write(zerologLine(t, "error", "plugin.go:1", "after-restart"))
	body := recvFrame(t, frames2)
	var got logger.LogRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Msg != "after-restart" {
		t.Errorf("Msg = %q, want after-restart", got.Msg)
	}
}

func TestWriter_FrameFormat(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read header: %v", err)
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 || length > logger.MaxFrameSize {
		t.Fatalf("length out of range: %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	var rec logger.LogRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Lineno != 7 || rec.Msg != "hi" {
		t.Errorf("unexpected record: %+v", rec)
	}
}
