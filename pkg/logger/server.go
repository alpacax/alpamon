package logger

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

type LogServer struct {
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

	// 0660: owner (root) rw, group rw, other none.
	// Group ownership is set to "alpamon" so plugin processes in that group
	// can connect without requiring root. Falls back silently if the group is absent.
	if err := os.Chmod(path, 0660); err != nil {
		log.Warn().Err(err).Msg("Failed to set log socket permissions.")
	}
	setAlpamonGroup(path)

	return &LogServer{
		listener:     listener,
		shutDownChan: make(chan struct{}),
		workerPool:   workerPool,
		ctxManager:   ctxManager,
	}
}

// setAlpamonGroup chowns path to root:alpamon so group members can connect.
// Silently skips if the alpamon group does not exist on this system.
func setAlpamonGroup(path string) {
	grp, err := user.LookupGroup("alpamon")
	if err != nil {
		return // alpamon group not provisioned yet; file ACL will be root-only
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return
	}
	if err := os.Lchown(path, 0, gid); err != nil {
		log.Warn().Err(err).Msg("Failed to set log socket group ownership.")
	}
}

func (ls *LogServer) StartLogServer() {
	log.Debug().Msgf("Started log server on %s.", socketPath())

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
	for {
		lengthBuf := make([]byte, 4)
		_, err := io.ReadFull(conn, lengthBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Warn().Err(err).Msg("Couldn't read message length from connection.")
			return
		}

		length := binary.BigEndian.Uint32(lengthBuf)
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
		err = json.Unmarshal(body, &record)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to unmarshal log record.")
			continue
		}

		go ls.handleRecord(record)
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
	_ = os.Remove(socketPath())
}
