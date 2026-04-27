package logger

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// maxFrameSize caps the length-prefix value to prevent a malformed or
// malicious client from triggering arbitrarily large heap allocations.
const maxFrameSize = 1 << 20 // 1 MiB

type LogServer struct {
	path         string
	listener     net.Listener
	shutDownChan chan struct{}
	workerPool   *pool.Pool
	ctxManager   *agent.ContextManager
}

func socketPath() string {
	return filepath.Join(utils.RunDir(), "logs.sock")
}

func NewLogServer(workerPool *pool.Pool, ctxManager *agent.ContextManager) *LogServer {
	path := socketPath()
	// Remove stale socket from a previous run.
	_ = os.Remove(path)

	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Error().Err(err).Msgf("Log server startup failed: cannot bind to %s.", path)
		return nil
	}

	return &LogServer{
		path:         path,
		listener:     listener,
		shutDownChan: make(chan struct{}),
		workerPool:   workerPool,
		ctxManager:   ctxManager,
	}
}

func (ls *LogServer) StartLogServer() {
	log.Debug().Msgf("Started log server on %s.", ls.path)

	for {
		select {
		case <-ls.shutDownChan:
			return
		default:
			conn, err := ls.listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Error().Err(err).Msg("Failed to accept socket.")
				continue
			}
			ctx, cancel := ls.ctxManager.NewContext(0)
			err = ls.workerPool.Submit(ctx, func() error {
				defer cancel()
				ls.handleConnection(conn)
				return nil
			})
			if err != nil {
				cancel()
				log.Error().Err(err).Msg("Failed to submit connection handler to pool")
				_ = conn.Close()
			}
		}
	}
}

func (ls *LogServer) handleConnection(conn net.Conn) {
	var lengthBuf [4]byte
	for {
		_, err := io.ReadFull(conn, lengthBuf[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Warn().Err(err).Msg("Couldn't read message length from connection.")
			return
		}

		length := binary.BigEndian.Uint32(lengthBuf[:])
		if length > maxFrameSize {
			log.Warn().Msgf("Log frame too large (%d bytes); closing connection.", length)
			return
		}
		body := make([]byte, length)
		_, err = io.ReadFull(conn, body)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Warn().Err(err).Msg("Failed to read log body.")
			return
		}

		var record LogRecord
		if err = json.Unmarshal(body, &record); err != nil {
			log.Debug().Err(err).Msg("Failed to unmarshal log record.")
			continue
		}

		ls.handleRecord(record)
	}
}

func (ls *LogServer) handleRecord(record LogRecord) {
	if scheduler.Rqueue == nil {
		return
	}
	scheduler.Rqueue.Post(recordURL, record, 90, time.Time{})
}

func (ls *LogServer) Stop() {
	close(ls.shutDownChan)
	_ = ls.listener.Close()
	_ = os.Remove(ls.path)
}
