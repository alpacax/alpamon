// Package wsclient is the WebSocket transport for connections to the Alpacon
// backhaul, packaged as a leaf so that modules outside this repository, such
// as the in-cluster alpamon-kube agent, can use it without compiling the host
// agent.
//
// A Client dials with the Authorization header the backhaul expects
// (id="...", key="..."), re-arms a read timeout before every read, and
// reconnects whenever the connection drops. Exponential backoff with jitter
// paces the attempts, including the redial after a connection that lasted
// less than MinBackoff, so a peer that accepts the handshake and drops it
// cannot draw a tight loop out of a fleet of agents. Everything it needs
// arrives through Config; nothing here reads
// alpamon's global settings. It reports connects, drops and retries through
// the hooks on Config instead of logging, so the caller decides where those
// go.
//
// # Ownership
//
// A Client owns its connection and never exposes it. Run is the only
// goroutine that reads, writes are serialized, and Shutdown and Reconnect
// only signal the read loop, so gorilla/websocket's rule of one concurrent
// reader and one concurrent writer holds by construction. A caller that needs
// a connection of its own, for example to wrap in tunnel.WebSocketConn for
// smux, uses Dial and takes on that responsibility itself.
//
// # Dependencies
//
// This package may import the standard library, github.com/gorilla/websocket,
// and alpamon's pkg/tunnel and pkg/version, and nothing else. The leaf-guard
// job in .github/workflows/build-and-test.yml fails the build if its
// dependency graph reaches any other package.
package wsclient
