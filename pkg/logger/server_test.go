package logger

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// runHandle invokes ls.handleConnection in a goroutine and signals when it
// returns. Used to assert that the server closes the connection in response
// to specific client behavior.
func runHandle(ls *LogServer, conn net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		ls.handleConnection(conn)
		close(done)
	}()
	return done
}

func waitDone(t *testing.T, done <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}
}

func TestHandleConnection_OversizedFrameClosesConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	ls := &LogServer{}
	done := runHandle(ls, server)

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	if _, err := client.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	waitDone(t, done, "handleConnection did not return on oversized frame")
}

func TestHandleConnection_ExitsOnClientClose(t *testing.T) {
	server, client := net.Pipe()

	ls := &LogServer{}
	done := runHandle(ls, server)

	_ = client.Close()
	waitDone(t, done, "handleConnection did not return after client close")
}
