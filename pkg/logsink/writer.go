// Package logsink provides a shared Unix-domain-socket writer for Alpamon plugins.
// Plugins use this package as an io.Writer target for zerolog so that their logs are
// forwarded to Alpamon and then on to the Alpacon server, without each plugin
// duplicating the filtering, framing, and reconnect logic.
package logsink

import (
	"encoding/binary"
	"encoding/json"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

const (
	dialTimeout    = 5 * time.Second
	reconnectDelay = 10 * time.Second

	socketName = "logs.sock"
)

// SocketPath returns the UDS path for the Alpamon log socket.
//
// The path is derived from utils.RunDir(), which differs by uid:
// /run/alpamon for root, /tmp/alpamon for non-root. This is safe today
// because both Alpamon and its plugins run as root; once privilege
// separation lands, this should switch to a fixed system path so
// non-root plugins still reach the daemon's socket.
func SocketPath() string {
	return filepath.Join(utils.RunDir(), socketName)
}

// Writer is a zerolog-compatible io.Writer that forwards filtered log records
// to alpamon over a Unix domain socket using the length-prefix wire protocol.
//
// Each Write call parses the zerolog JSON line, checks whether the source file
// and level pass the plugin-specific handlers filter, builds a LogRecord, and
// sends it framed as [uint32 BE length][JSON body]. Connection errors are
// silent and the writer reconnects automatically after a short cooldown.
type Writer struct {
	program  string
	pid      int
	handlers map[string]int // filename → minimum Python log level
	path     string

	mu       sync.Mutex
	conn     net.Conn
	lastFail time.Time
}

// New returns a Writer for the given plugin. program is used as the LogRecord.Program
// field. handlers maps base filenames to their minimum log level threshold
// (using Python logging levels: 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL).
// Connection failure at construction time is non-fatal; the writer will retry.
func New(program string, handlers map[string]int) *Writer {
	h := make(map[string]int, len(handlers))
	maps.Copy(h, handlers)
	w := &Writer{
		program:  program,
		pid:      os.Getpid(),
		handlers: h,
		path:     SocketPath(),
	}
	w.conn, _ = net.DialTimeout("unix", w.path, dialTimeout)
	return w
}

// Write implements io.Writer. p is expected to be a single zerolog JSON line.
// Always returns (len(p), nil) to prevent zerolog from logging internal errors.
func (w *Writer) Write(p []byte) (int, error) {
	var entry logger.ZerologEntry
	if err := json.Unmarshal(p, &entry); err != nil {
		return len(p), nil
	}
	if entry.Caller == "" {
		return len(p), nil
	}

	callerFileName, lineNo := logger.ParseCaller(entry.Caller)
	threshold, ok := w.handlers[callerFileName]
	if !ok {
		return len(p), nil
	}
	level := logger.ConvertLevelToNumber(entry.Level)
	if level < threshold {
		return len(p), nil
	}

	record := logger.LogRecord{
		Date:    entry.Time,
		Level:   level,
		Program: w.program,
		Path:    entry.Caller,
		Lineno:  lineNo,
		PID:     w.pid,
		Msg:     entry.Message,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return len(p), nil
	}

	// Build [uint32 BE length][JSON body] frame in a single allocation.
	// Drop records that exceed the server's MaxFrameSize — the server would
	// close the connection on receipt, triggering reconnect cooldown.
	if len(data) > logger.MaxFrameSize {
		return len(p), nil
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn == nil {
		w.tryReconnect()
	}
	if w.conn == nil {
		return len(p), nil // socket unavailable; drop silently
	}
	if _, err := w.conn.Write(frame); err != nil {
		_ = w.conn.Close()
		w.conn = nil
		w.lastFail = time.Now()
	}
	return len(p), nil
}

// Close closes the underlying connection.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		err := w.conn.Close()
		w.conn = nil
		return err
	}
	return nil
}

// tryReconnect attempts a single reconnect if the cooldown has elapsed.
// Must be called with w.mu held.
func (w *Writer) tryReconnect() {
	if time.Since(w.lastFail) < reconnectDelay {
		return
	}
	conn, err := net.DialTimeout("unix", w.path, dialTimeout)
	if err != nil {
		w.lastFail = time.Now()
		return
	}
	w.conn = conn
}
