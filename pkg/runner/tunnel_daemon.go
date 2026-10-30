package runner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Shared by the Unix daemon and the Windows direct-dial path.
const (
	tunnelDialTimeout     = 10 * time.Second
	tunnelKeepAlivePeriod = 30 * time.Second

	// The only host a relay target or a code-server bind may name.
	loopbackHost = "127.0.0.1"
)

// validateTargetAddr ensures the target address is a literal loopback endpoint,
// so the tunnel cannot be used to reach arbitrary hosts. This is the only
// boundary on the Windows path, where the relay dials from the agent process
// itself, so it parses the host rather than matching a prefix and rejects names
// outright: a name would hand the decision to whatever the resolver says.
// Every caller formats the address from a port, so no name is ever passed.
func validateTargetAddr(targetAddr string) bool {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// dialDirect dials targetAddr over TCP with relay tuning applied, rejecting
// anything that is not a loopback address. Used by the Unix daemon and as the
// whole relay path on Windows.
func dialDirect(targetAddr string) (net.Conn, error) {
	if !validateTargetAddr(targetAddr) {
		return nil, fmt.Errorf("invalid target address %s: must be a loopback address", targetAddr)
	}

	conn, err := net.DialTimeout("tcp", targetAddr, tunnelDialTimeout)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(tunnelKeepAlivePeriod)
	}

	return conn, nil
}

// RunTunnelDaemon serves the tunnel-daemon subcommand, which is registered on
// Unix only, relaying Unix domain socket connections to local TCP services. A
// root parent demotes it to nobody.
func RunTunnelDaemon(socketPath string) {
	listener, err := utils.ListenUnixPrivate(socketPath)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to listen on socket %s.", socketPath)
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
		_ = listener.Close()
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

	_ = listener.Close()
	log.Info().Msg("Tunnel daemon stopped.")
}

// handleDaemonConnection handles a single relay request from the main process.
// It reads the target address from the first line, connects to the local service,
// and relays data bidirectionally between the UDS connection and the TCP connection.
func handleDaemonConnection(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { _ = conn.Close() }()

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

	// Redundant with dialDirect, kept so a rejected target is visible at error
	// level rather than only in dialDirect's debug log.
	if !validateTargetAddr(targetAddr) {
		log.Error().Str("targetAddr", targetAddr).Msg("Invalid target address: must be a loopback address.")
		return
	}

	tcpConn, err := dialDirect(targetAddr)
	if err != nil {
		log.Debug().Err(err).Msgf("Tunnel daemon failed to connect to %s.", targetAddr)
		return
	}
	defer func() { _ = tcpConn.Close() }()

	log.Debug().Msgf("Tunnel daemon connected to %s.", targetAddr)

	relayBidirectional(conn, reader, tcpConn, tcpConn)
	log.Debug().Msgf("Tunnel daemon relay finished for %s.", targetAddr)
}
