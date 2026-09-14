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
// arrives through Config; nothing here reads alpamon's global settings. It
// reports connects, drops and retries through the hooks on Config instead of
// logging, so the caller decides where those go.
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
//
// That list is the ceiling, not an inventory. What ships imports pkg/version,
// for the default User-Agent, and gorilla/websocket; pkg/tunnel is allowed
// for the caller in Ownership above, who wraps what Dial returns, and is not
// reached from here. The list is repeated in the job's own ALLOWED variable,
// and the job is the one that decides.
//
// # Relation to pkg/runner
//
// pkg/runner still carries WebSocket clients of its own, and the same numbers
// are written out in both places: the 35-minute read timeout, the 5s and 60s
// reconnect bounds, the Authorization format, and a close-frame-then-drain-
// then-close sequence. The schedules have already drifted, with internal/retry
// drawing its jitter factor from [0.5, 1.5) and this package from [1.0, 1.5).
//
// They are meant to converge here rather than be kept in step by hand:
// pkg/runner may import this package, and issue #452, which this package
// avoids by construction and pkg/runner still has, is the reason to. Until
// that lands, a change to either one is a change both copies need.
package wsclient
