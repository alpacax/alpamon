package runner

import (
	"bufio"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/pkg/tunnel"
	"github.com/rs/zerolog/log"
)

// validateTargetAddr ensures the target address is localhost only for security.
// This prevents the tunnel from being used to connect to arbitrary external hosts.
func validateTargetAddr(targetAddr string) bool {
	return strings.HasPrefix(targetAddr, "127.0.0.1:") || strings.HasPrefix(targetAddr, "localhost:")
}

// RunTunnelDaemon runs the tunnel daemon subprocess.
// It listens on a Unix domain socket and relays connections to local TCP services.
// This function is called by the tunnel-daemon subcommand and runs with demoted user credentials.
func RunTunnelDaemon(socketPath string) {
	// Remove stale socket file if it exists
	if _, err := os.Stat(socketPath); err == nil {
		os.Remove(socketPath)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to listen on socket %s.", socketPath)
		os.Exit(1)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		log.Error().Err(err).Msgf("Failed to set socket permissions for %s.", socketPath)
		os.Exit(1)
	}

	log.Info().Msgf("Tunnel daemon listening on %s.", socketPath)

	// Signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup

	go func() {
		<-sigChan
		log.Info().Msg("Tunnel daemon received shutdown signal.")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed (shutdown signal or error)
			break
		}

		wg.Add(1)
		go handleDaemonConnection(conn, &wg)
	}

	// Wait for active relays to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("All tunnel daemon relays finished.")
	case <-time.After(5 * time.Second):
		log.Warn().Msg("Tunnel daemon shutdown timed out, forcing exit.")
	}

	os.Remove(socketPath)
	log.Info().Msg("Tunnel daemon stopped.")
}

// handleDaemonConnection handles a single relay request from the main process.
// It reads the target address from the first line, connects to the local service,
// and relays data bidirectionally between the UDS connection and the TCP connection.
func handleDaemonConnection(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	// Read target address from first line
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		// EOF without data is a readiness probe from waitForDaemonReady(), not an error.
		if err != io.EOF {
			log.Debug().Err(err).Msg("Failed to read target address from daemon connection.")
		}
		return
	}

	targetAddr := strings.TrimSpace(line)

	// Security: Only allow connections to localhost
	if !validateTargetAddr(targetAddr) {
		log.Error().Str("targetAddr", targetAddr).Msg("Invalid target address: must be localhost (127.0.0.1 or localhost).")
		return
	}

	tcpConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Debug().Err(err).Msgf("Tunnel daemon failed to connect to %s.", targetAddr)
		return
	}
	defer tcpConn.Close()

	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	log.Debug().Msgf("Tunnel daemon connected to %s.", targetAddr)

	// Bidirectional relay between UDS connection and TCP connection
	errChan := make(chan error, 2)

	// UDS -> TCP
	go func() {
		_, err := tunnel.CopyBuffered(tcpConn, reader)
		errChan <- err
	}()

	// TCP -> UDS
	go func() {
		_, err := tunnel.CopyBuffered(conn, tcpConn)
		errChan <- err
	}()

	// Wait for one direction to complete
	<-errChan
	log.Debug().Msgf("Tunnel daemon relay finished for %s.", targetAddr)
}
