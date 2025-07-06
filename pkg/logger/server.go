package logger

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

const (
	address = "0.0.0.0:9020"
)

type LogServer struct {
	listener     net.Listener
	shutDownChan chan struct{}
}

func NewLogServer() *LogServer {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Error().Err(err).Msgf("Log server startup failed: cannot bind to %s.", address)
		return nil
	}

	return &LogServer{
		listener:     listener,
		shutDownChan: make(chan struct{}),
	}
}

func (ls *LogServer) StartLogServer() {
	log.Debug().Msgf("Started log server on %s.", address)

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
			go ls.handleConnection(conn)
		}
	}
}

func (ls *LogServer) handleConnection(conn net.Conn) {
	for {
		lengthBuf := make([]byte, 4)
		_, err := io.ReadFull(conn, lengthBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return // connection closed by client, terminating read loop
			}
			log.Warn().Err(err).Msg("Couldn't read message length from connection.")
			return
		}

		length := binary.BigEndian.Uint32(lengthBuf)
		body := make([]byte, length)
		_, err = io.ReadFull(conn, body)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return // connection closed by client, terminating read loop
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
}
