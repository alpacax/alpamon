package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/alpacax/alpamon/v2/internal/retry"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	// authRejectionThreshold is how many connection attempts must be
	// rejected with no successful connection in between, and
	// authRejectionSpan how long that streak must have been running, before
	// the agent slows down to authRejectedInterval. Both conditions have to
	// hold: the count alone would fire on a burst of quick retries during a
	// restart, and the span alone on a single rejection followed by half an
	// hour of something else. With the ordinary 5s-to-60s backoff the span
	// is the binding one, which is the intent - the question is whether the
	// server has been refusing the credentials for a while, not how many
	// packets that took.
	authRejectionThreshold = 5
	authRejectionSpan      = 30 * time.Minute

	// authRejectedInterval is the base wait between attempts once the
	// streak is established. The wait actually used is 0.5x to 1.5x this,
	// the same jitter the ordinary backoff applies, so agents refused by
	// one event spread themselves over 30 to 90 minutes instead of arriving
	// together.
	authRejectedInterval = 1 * time.Hour

	// handshakeTimeout bounds the HTTP upgrade exchange, which the dial
	// context no longer covers once the socket is up. It is gorilla's own
	// default for websocket.DefaultDialer; a server that needs longer than
	// this to answer an upgrade is not one worth waiting on.
	handshakeTimeout = 45 * time.Second
)

// handshakeError carries the HTTP status a rejected WebSocket handshake came
// back with. gorilla/websocket reports every rejected handshake as the same
// websocket.ErrBadHandshake and hands the response to the caller separately,
// so without keeping the status a 401 is indistinguishable from a refused
// TCP connection.
type handshakeError struct {
	StatusCode int
	Err        error
}

func (e *handshakeError) Error() string {
	return fmt.Sprintf("%v (HTTP %d)", e.Err, e.StatusCode)
}

func (e *handshakeError) Unwrap() error { return e.Err }

// isAuthRejection reports whether err is a handshake the server refused on
// the agent's credentials rather than one it could not serve: unauthorized,
// forbidden, or no such server registered. Everything else, including 5xx
// and every transport error, is treated as a server that is temporarily
// unwell and keeps the ordinary backoff.
func isAuthRejection(err error) bool {
	var handshake *handshakeError
	if !errors.As(err, &handshake) {
		return false
	}

	switch handshake.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

// dialWebsocket opens one connection to url. A handshake the server answered
// and rejected comes back as a *handshakeError, so the caller can tell a
// refused credential from an unreachable server. Only the status is kept:
// the response also carries the request, and with it the Authorization
// header, which has no business travelling with an error.
//
// ctx bounds the TCP and TLS phases. gorilla/websocket stops watching it
// once the socket is up, so HandshakeTimeout bounds the HTTP upgrade
// exchange after that; without one, a peer that accepts the connection and
// then says nothing parks this call, and with it a shutdown, indefinitely.
func dialWebsocket(ctx context.Context, url string, header http.Header) (*websocket.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
		},
	}

	conn, resp, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		if resp == nil {
			return nil, err
		}
		return nil, &handshakeError{StatusCode: resp.StatusCode, Err: err}
	}

	return conn, nil
}

// authBackoff paces reconnect attempts. It is the ordinary exponential
// backoff until the server has been refusing this agent's credentials long
// enough that retrying every minute is pointless, and a long jittered
// interval after that. Only a connection that comes up clears it, and the
// agent keeps trying either way: it never uninstalls itself and never exits,
// because a rejection can also be a mistake someone is about to undo.
type authBackoff struct {
	threshold int
	span      time.Duration
	interval  time.Duration

	// now and rand are indirected so tests can drive the state machine
	// without a clock or a random source.
	now  func() time.Time
	rand func() float64

	backoff   retry.ExponentialBackoff
	count     int
	first     time.Time
	escalated bool
}

func newAuthBackoff(initialInterval, maxInterval time.Duration) *authBackoff {
	return &authBackoff{
		threshold: authRejectionThreshold,
		span:      authRejectionSpan,
		interval:  authRejectedInterval,
		now:       time.Now,
		rand:      rand.Float64,
		backoff: retry.ExponentialBackoff{
			InitialInterval: initialInterval,
			MaxInterval:     maxInterval,
		},
	}
}

// next records one failed attempt and returns how long to wait before the
// next one. escalated is true only on the attempt that crosses the
// threshold, so the caller warns once per streak instead of once an hour.
//
// A failure that is not an authentication rejection - a refused connection,
// a timeout, a 5xx - neither counts towards the streak nor clears it. It
// cannot show the credentials are accepted again, and clearing on it would
// mean an agent on a flaky link never slows down however long it has been
// refused.
func (a *authBackoff) next(err error) (wait time.Duration, escalated bool) {
	if isAuthRejection(err) {
		now := a.now()
		if a.count == 0 {
			a.first = now
		}
		a.count++

		if !a.escalated && a.count >= a.threshold && !now.Before(a.first.Add(a.span)) {
			a.escalated = true
			escalated = true
		}
	}

	if a.escalated {
		return a.longInterval(), escalated
	}

	return a.backoff.NextBackOff(), false
}

// success clears the streak, so a connection that comes up puts the agent
// back on the short interval for whatever disconnects it next.
func (a *authBackoff) success() {
	a.count = 0
	a.first = time.Time{}
	a.escalated = false
	a.backoff.Reset()
}

// longInterval applies the same 0.5x-to-1.5x jitter the ordinary backoff
// uses. It is not clamped: the point of the interval is to be long, and the
// spread is what keeps refused agents from retrying in lockstep.
func (a *authBackoff) longInterval() time.Duration {
	return time.Duration(float64(a.interval) * (0.5 + a.rand()))
}

// connectForever calls dial until it succeeds or ctx ends, pacing attempts
// with a. There is no overall deadline on purpose: the loop used to give up
// after three days and exit, which only handed the same loop back to the
// service manager to start over, having lost the agent in the meantime.
func connectForever(ctx context.Context, a *authBackoff, endpoint string, dial func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := dial()
		if err == nil {
			if a.escalated {
				log.Info().Msgf("Connection to %s was accepted, returning to the normal reconnect interval.", endpoint)
			}
			a.success()
			return nil
		}

		wait, escalated := a.next(err)
		if escalated {
			// Not "consecutive attempts": next deliberately keeps the
			// streak across transport errors and 5xx, so attempts that
			// failed for another reason may sit between these rejections.
			log.Warn().Msgf("The server has rejected this agent's credentials %d times while connecting to %s, over the last %s, with no connection accepted in between. Reconnecting about once an hour from now on.",
				a.count, endpoint, a.span)
		} else {
			log.Debug().Err(err).Msgf("Failed to connect to %s, retrying in %s...", endpoint, wait.Round(time.Second))
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
