package runner

import (
	"io"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

// RunTunnelWorker runs the tunnel worker subprocess.
// It connects to the target address and relays data between stdin/stdout and the TCP connection.
// This function is called by the tunnel-worker subcommand and runs with demoted user credentials.
func RunTunnelWorker(targetAddr string) {
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Error().Err(err).Msgf("Tunnel worker failed to connect to %s.", targetAddr)
		os.Exit(1)
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	log.Debug().Msgf("Tunnel worker connected to %s.", targetAddr)

	// Bidirectional relay between stdin/stdout and TCP connection
	errChan := make(chan error, 2)

	// stdin -> TCP
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		errChan <- err
	}()

	// TCP -> stdout
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		errChan <- err
	}()

	// Wait for one direction to complete
	<-errChan
	log.Debug().Msgf("Tunnel worker finished for %s.", targetAddr)
}
