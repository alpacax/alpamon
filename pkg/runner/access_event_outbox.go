package runner

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/accesseventoutbox"
	"github.com/rs/zerolog/log"
)

const (
	// accessOutboxMaxRows and accessOutboxMaxAge bound what an outage can
	// leave on disk, whichever is reached first. A row is at most a few KB (the
	// strings are capped at the server's limits), so the count bound keeps the
	// table in the tens of MB.
	accessOutboxMaxRows = 10000
	accessOutboxMaxAge  = 30 * 24 * time.Hour

	// accessOutboxSendInterval paces delivery to five events a second, below
	// the server's per-agent ingest throttle, so draining a backlog does not
	// turn into a run of 429s.
	accessOutboxSendInterval = time.Second / 5

	accessOutboxMinBackoff = time.Second
	accessOutboxMaxBackoff = 10 * time.Minute
	// accessOutboxMaxRetryAfter caps a server's Retry-After, so one bogus
	// value cannot park the outbox for days.
	accessOutboxMaxRetryAfter = time.Hour
	// accessOutboxMaxDelay is the longest wait any response can schedule,
	// jitter included. A wait longer than this can only come from the wall
	// clock being set back, and is treated as already over.
	accessOutboxMaxDelay = accessOutboxMaxRetryAfter + accessOutboxMaxRetryAfter/5

	// accessOutboxReachableJitter spreads the first drain after startup and
	// after the server becomes reachable again, so a fleet that lost the
	// server together does not drain into it together.
	accessOutboxReachableJitter = 30 * time.Second

	// accessOutboxRowFailureStreak is how many consecutive events failing
	// with a server error the drain takes as the server being down rather
	// than one event it cannot process.
	accessOutboxRowFailureStreak = 3

	accessOutboxMinWait     = 50 * time.Millisecond
	accessOutboxBatchSize   = 50
	accessOutboxPostTimeout = 10 // seconds, the unit scheduler.Session takes
	accessOutboxDBTimeout   = 5 * time.Second
	accessOutboxDropWarnGap = time.Minute
	accessOutboxStopTimeout = 5 * time.Second
)

// accessOutboxIdle is what drainOnce returns when nothing is waiting: the
// drain sleeps until a new event or a reachability signal arrives.
const accessOutboxIdle = time.Duration(-1)

// accessEventSender delivers one event and reports the HTTP status and any
// Retry-After the server sent. A non-nil error means no response arrived.
type accessEventSender func(ctx context.Context, event NonAlpaconAccessEvent) (status int, retryAfter time.Duration, err error)

type accessDeliveryVerdict int

const (
	verdictDelivered accessDeliveryVerdict = iota
	// verdictHoldServer means the server as a whole is unavailable: no
	// answer, a throttle, a gateway error, or a 404 from an endpoint that
	// has answered before. Delivery pauses for every event.
	verdictHoldServer
	// verdictHoldEvent is a server error that may be about this one event.
	// Only this event backs off unless several in a row fail the same way.
	verdictHoldEvent
	verdictDrop
	// verdictDropQuiet is a 404 before any delivery has succeeded: a server
	// that predates the endpoint, which is a normal state, not a failure.
	verdictDropQuiet
)

// classifyAccessDelivery maps one delivery attempt to what the outbox does
// with the event.
func classifyAccessDelivery(status int, err error, endpointSeen bool) accessDeliveryVerdict {
	switch {
	case err != nil:
		return verdictHoldServer
	case status >= 200 && status < 300:
		return verdictDelivered
	case status == http.StatusNotFound:
		if endpointSeen {
			return verdictHoldServer
		}
		return verdictDropQuiet
	case status == http.StatusTooManyRequests,
		status == http.StatusRequestTimeout,
		status == http.StatusTooEarly,
		status == http.StatusBadGateway,
		status == http.StatusServiceUnavailable,
		status == http.StatusGatewayTimeout:
		return verdictHoldServer
	case status >= 400 && status < 500:
		// 400, 401, 403 and the rest: the server will not take this event
		// however often it is sent.
		return verdictDrop
	default:
		return verdictHoldEvent
	}
}

// accessEventOutbox holds login events in the agent's database until the
// server has them. Events are written before any delivery is tried, so a
// server outage, an agent restart or a shutdown delays them rather than
// losing them, and one goroutine delivers them oldest first.
//
// The only loss window is between the PAM ack and the insert committing: a
// crash there loses that event. Past that, an event leaves the table only by
// being delivered, being refused by the server, or falling outside the bounds
// above.
type accessEventOutbox struct {
	client *ent.Client
	send   accessEventSender

	// Replaced in tests.
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error
	jitter  func(limit time.Duration) time.Duration
	maxRows int
	maxAge  time.Duration

	wake      chan struct{}
	reachable chan struct{}
	done      chan struct{}

	// endpointSeen latches once the endpoint has answered 2xx in this
	// process, which is what turns a later 404 from "server predates the
	// endpoint" into "hold and retry".
	endpointSeen atomic.Bool

	// inflight counts enqueue calls in progress, so stop can let an event
	// that was already acked reach the disk.
	inflightMu sync.Mutex
	inflight   sync.WaitGroup
	stopping   bool

	// Drain state, owned by the drain goroutine.
	gate          time.Time // no send before this
	gateFromRetry bool      // the gate came from the server's Retry-After
	failures      int       // consecutive held deliveries
	outage        bool      // a server-wide failure since the last delivery
	lastSucceeded bool      // the previous send was delivered
	lastSend      time.Time
	recovering    bool // count deliveries for the after-outage Info line
	recovered     int
	dbFailures    int

	dropMu       sync.Mutex
	droppedQuiet int
	lastDropWarn time.Time
}

func newAccessEventOutbox(client *ent.Client, send accessEventSender) *accessEventOutbox {
	return &accessEventOutbox{
		client:    client,
		send:      send,
		now:       time.Now,
		sleep:     sleepCtx,
		jitter:    randomJitter,
		maxRows:   accessOutboxMaxRows,
		maxAge:    accessOutboxMaxAge,
		wake:      make(chan struct{}, 1),
		reachable: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
}

func randomJitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return rand.N(limit)
}

// accessOutboxBackoff is the wait after the nth consecutive failure: one
// second doubling to ten minutes, plus up to a fifth of that as jitter.
func accessOutboxBackoff(n int, jitter func(time.Duration) time.Duration) time.Duration {
	d := accessOutboxMinBackoff
	for i := 1; i < n && d < accessOutboxMaxBackoff; i++ {
		d *= 2
	}
	d = min(d, accessOutboxMaxBackoff)
	return d + jitter(d/5)
}

// parseRetryAfter reads a Retry-After value in either form RFC 9110 allows,
// delay-seconds or an HTTP date. It returns zero when the header is absent or
// unusable, and caps the result at accessOutboxMaxRetryAfter.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var d time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int64(accessOutboxMaxRetryAfter/time.Second) {
			return accessOutboxMaxRetryAfter
		}
		d = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		d = at.Sub(now)
	}
	if d <= 0 {
		return 0
	}
	return min(d, accessOutboxMaxRetryAfter)
}

// enqueue stores an accepted event. It runs on the auth socket goroutine after
// the PAM ack has been written, so it adds nothing to the login. It does not
// observe the agent's context: an event that was acked is written even while
// the agent shuts down.
func (o *accessEventOutbox) enqueue(event NonAlpaconAccessEvent) {
	o.inflightMu.Lock()
	tracked := !o.stopping
	if tracked {
		o.inflight.Add(1)
	}
	o.inflightMu.Unlock()
	if tracked {
		defer o.inflight.Done()
	}

	// Stored without held_seconds; that is worked out at each send.
	event.HeldSeconds = 0
	payload, err := json.Marshal(event)
	if err != nil {
		log.Warn().Err(err).Str("event_id", event.EventID).Msg("Failed to encode access event; dropping")
		return
	}
	createdAt := event.Timestamp
	if createdAt.IsZero() {
		createdAt = o.now()
	}
	createdAt = createdAt.UTC()

	ctx, cancel := context.WithTimeout(context.Background(), accessOutboxDBTimeout)
	defer cancel()

	err = retrySQLiteBusy(ctx, func() error {
		return o.client.AccessEventOutbox.Create().
			SetID(event.EventID).
			SetPayload(payload).
			SetCreatedAt(createdAt).
			SetNextAttemptAt(o.now().UTC()).
			Exec(ctx)
	})
	if ent.IsConstraintError(err) {
		// Already held: the server deduplicates on event_id, so one row is
		// all the delivery needs.
		log.Debug().Str("event_id", event.EventID).Msg("Access event already held")
		return
	}
	if err != nil {
		log.Warn().Err(err).Str("event_id", event.EventID).Msg("Failed to store access event; dropping")
		return
	}
	log.Debug().Str("event_id", event.EventID).Msg("Access event stored for delivery")

	o.trimToMaxRows(ctx)
	nudge(o.wake)
}

// trimToMaxRows drops the oldest rows past maxRows.
func (o *accessEventOutbox) trimToMaxRows(ctx context.Context) {
	var count int
	err := retrySQLiteBusy(ctx, func() error {
		var err error
		count, err = o.client.AccessEventOutbox.Query().Count(ctx)
		return err
	})
	if err != nil || count <= o.maxRows {
		return
	}
	var ids []string
	err = retrySQLiteBusy(ctx, func() error {
		var err error
		ids, err = o.client.AccessEventOutbox.Query().
			Order(ent.Asc(accesseventoutbox.FieldCreatedAt), ent.Asc(accesseventoutbox.FieldID)).
			Limit(count - o.maxRows).
			IDs(ctx)
		return err
	})
	if err != nil || len(ids) == 0 {
		return
	}
	var dropped int
	err = retrySQLiteBusy(ctx, func() error {
		var err error
		dropped, err = o.client.AccessEventOutbox.Delete().Where(accesseventoutbox.IDIn(ids...)).Exec(ctx)
		return err
	})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to trim the access event outbox")
		return
	}
	o.noteDropped(dropped)
}

// noteDropped reports events lost to the outbox bounds: one Warn a minute at
// most, carrying every drop since the previous one.
func (o *accessEventOutbox) noteDropped(n int) {
	if n <= 0 {
		return
	}
	now := o.now()
	o.dropMu.Lock()
	o.droppedQuiet += n
	if !o.lastDropWarn.IsZero() && now.Sub(o.lastDropWarn) < accessOutboxDropWarnGap {
		o.dropMu.Unlock()
		log.Debug().Int("dropped", n).Msg("Dropped held access events past the outbox bounds")
		return
	}
	count := o.droppedQuiet
	o.droppedQuiet = 0
	o.lastDropWarn = now
	o.dropMu.Unlock()

	log.Warn().
		Int("dropped", count).
		Int("max_events", o.maxRows).
		Dur("max_age", o.maxAge).
		Msg("Dropped the oldest held access events: the outbox is past its bounds")
}

// start launches the drain goroutine. stop joins it.
func (o *accessEventOutbox) start(ctx context.Context) {
	go o.run(ctx)
}

// stop waits, up to timeout, for in-progress inserts and for the drain
// goroutine, whose context the caller has already cancelled. It reports
// whether both finished.
func (o *accessEventOutbox) stop(timeout time.Duration) bool {
	o.inflightMu.Lock()
	o.stopping = true
	o.inflightMu.Unlock()

	inserted := make(chan struct{})
	go func() {
		o.inflight.Wait()
		close(inserted)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for _, ch := range []<-chan struct{}{inserted, o.done} {
		select {
		case <-ch:
		case <-timer.C:
			return false
		}
	}
	return true
}

// notifyReachable tells the drain the server answered on another channel, so
// a long backoff can end early.
func (o *accessEventOutbox) notifyReachable() {
	nudge(o.reachable)
}

func nudge(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (o *accessEventOutbox) run(ctx context.Context) {
	defer close(o.done)
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Access event outbox drain panicked")
		}
	}()

	if o.pending(ctx) {
		// Held from a previous run. Spread the first drain, since agents
		// restarted together would otherwise drain together.
		o.recovering = true
		o.gate = o.now().Add(o.jitter(accessOutboxReachableJitter))
	}

	for {
		wait := o.drainOnce(ctx)

		var timer *time.Timer
		var fire <-chan time.Time
		if wait >= 0 {
			timer = time.NewTimer(wait)
			fire = timer.C
		}
		select {
		case <-ctx.Done():
		case <-o.wake:
		case <-o.reachable:
			o.onReachable()
		case <-fire:
		}
		if timer != nil {
			timer.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// onReachable ends a backoff early once the server is known to answer again.
// A Retry-After is the server's own instruction and stands.
func (o *accessEventOutbox) onReachable() {
	if o.failures == 0 || o.gateFromRetry {
		return
	}
	if at := o.now().Add(o.jitter(accessOutboxReachableJitter)); at.Before(o.gate) {
		o.gate = at
	}
}

func (o *accessEventOutbox) pending(ctx context.Context) bool {
	var exists bool
	err := retrySQLiteBusy(ctx, func() error {
		var err error
		exists, err = o.client.AccessEventOutbox.Query().Exist(ctx)
		return err
	})
	return err == nil && exists
}

// drainOnce delivers every event that is due, oldest first and paced, and
// returns how long to wait before the next pass, or accessOutboxIdle.
func (o *accessEventOutbox) drainOnce(ctx context.Context) time.Duration {
	o.purgeExpired(ctx)

	for ctx.Err() == nil {
		now := o.now()
		if wait := o.gate.Sub(now); wait > 0 && wait <= accessOutboxMaxDelay {
			return wait
		}

		rows, err := o.dueRows(ctx, now)
		if err != nil {
			return o.dbFailed(err)
		}
		o.dbFailures = 0
		if len(rows) == 0 {
			o.finishRecovery()
			return o.untilNextDue(ctx, now)
		}

		for _, row := range rows {
			if err := o.pace(ctx); err != nil {
				return 0
			}
			verdict, stop := o.deliver(ctx, row)
			if stop {
				if ctx.Err() != nil {
					return 0
				}
				return max(0, o.gate.Sub(o.now()))
			}
			if verdict == verdictDelivered && o.outage {
				// The server is back. Events deferred during the outage are
				// due now, and the next query picks them up oldest first.
				o.outage = false
				o.releaseDeferred(ctx)
				break
			}
		}
	}
	return 0
}

// dueRows returns the next batch of events whose attempt time has come, oldest
// first. An attempt time further out than any response could schedule means
// the wall clock was set back, and counts as due.
func (o *accessEventOutbox) dueRows(ctx context.Context, now time.Time) ([]*ent.AccessEventOutbox, error) {
	utc := now.UTC()
	var rows []*ent.AccessEventOutbox
	err := retrySQLiteBusy(ctx, func() error {
		var err error
		rows, err = o.client.AccessEventOutbox.Query().
			Where(accesseventoutbox.Or(
				accesseventoutbox.NextAttemptAtLTE(utc),
				accesseventoutbox.NextAttemptAtGT(utc.Add(accessOutboxMaxDelay)),
			)).
			Order(ent.Asc(accesseventoutbox.FieldCreatedAt), ent.Asc(accesseventoutbox.FieldID)).
			Limit(accessOutboxBatchSize).
			All(ctx)
		return err
	})
	return rows, err
}

// untilNextDue returns the wait until the earliest held event is due, or
// accessOutboxIdle when nothing is held.
func (o *accessEventOutbox) untilNextDue(ctx context.Context, now time.Time) time.Duration {
	var next *ent.AccessEventOutbox
	err := retrySQLiteBusy(ctx, func() error {
		var err error
		next, err = o.client.AccessEventOutbox.Query().
			Order(ent.Asc(accesseventoutbox.FieldNextAttemptAt)).
			First(ctx)
		return err
	})
	if ent.IsNotFound(err) {
		return accessOutboxIdle
	}
	if err != nil {
		return o.dbFailed(err)
	}
	// The floor keeps a row the due query did not return, however that came
	// about, from turning the drain into a spin.
	wait := next.NextAttemptAt.Sub(now)
	return max(accessOutboxMinWait, min(wait, accessOutboxMaxDelay))
}

func (o *accessEventOutbox) dbFailed(err error) time.Duration {
	o.dbFailures++
	log.Debug().Err(err).Msg("Access event outbox query failed")
	return accessOutboxBackoff(o.dbFailures, o.jitter)
}

// pace holds sends to accessOutboxSendInterval apart.
func (o *accessEventOutbox) pace(ctx context.Context) error {
	if !o.lastSend.IsZero() {
		wait := o.lastSend.Add(accessOutboxSendInterval).Sub(o.now())
		// More than one interval can only be the clock moving backwards.
		wait = min(wait, accessOutboxSendInterval)
		if wait > 0 {
			if err := o.sleep(ctx, wait); err != nil {
				return err
			}
		}
	}
	o.lastSend = o.now()
	return ctx.Err()
}

// deliver sends one held event and settles its row. stop reports that the
// pass must end, because delivery is paused or the agent is stopping.
func (o *accessEventOutbox) deliver(ctx context.Context, row *ent.AccessEventOutbox) (verdict accessDeliveryVerdict, stop bool) {
	var event NonAlpaconAccessEvent
	if err := json.Unmarshal(row.Payload, &event); err != nil {
		log.Warn().Str("event_id", row.ID).Msg("Held access event is unreadable; dropping")
		o.remove(ctx, row.ID)
		return verdictDrop, false
	}

	now := o.now()
	// Seconds since capture by the host clock; a clock set back since then
	// gives a negative hold, which is sent as none.
	if held := int64(now.UTC().Sub(row.CreatedAt) / time.Second); held > 0 {
		event.HeldSeconds = held
	}

	status, retryAfter, err := o.send(ctx, event)
	if ctx.Err() != nil {
		// Stopping. Whether or not the server got it, the row stays and the
		// next run resends it; the server deduplicates on event_id.
		return verdictHoldServer, true
	}

	verdict = classifyAccessDelivery(status, err, o.endpointSeen.Load())
	if verdict == verdictHoldServer && o.lastSucceeded && row.Attempts > 0 && retryAfter == 0 {
		// The send before this one went through, and this event has failed
		// before: the failure is more likely this event than the server.
		// Holding only it keeps one event the server cannot take from
		// pausing, and then re-releasing, everything behind it.
		verdict = verdictHoldEvent
	}
	o.lastSucceeded = verdict == verdictDelivered
	switch verdict {
	case verdictDelivered:
		o.endpointSeen.Store(true)
		o.failures = 0
		o.gate = time.Time{}
		o.gateFromRetry = false
		if o.recovering {
			o.recovered++
		}
		log.Debug().Str("event_id", row.ID).Int("status", status).Int64("held_seconds", event.HeldSeconds).
			Msg("Access event delivered")
		o.remove(ctx, row.ID)
		return verdict, false

	case verdictDropQuiet:
		log.Debug().Str("event_id", row.ID).
			Msg("Access event endpoint not available on this server (404); dropping event")
		o.remove(ctx, row.ID)
		return verdict, false

	case verdictDrop:
		log.Warn().Str("event_id", row.ID).Int("status", status).
			Msg("Access event rejected by server; dropping event")
		o.remove(ctx, row.ID)
		return verdict, false
	}

	// Held. The row backs off on its own count, so an event the server keeps
	// failing on cannot hold up the ones behind it. When the whole queue
	// pauses, the row waits one step longer than the queue does, so the next
	// probe is a different event rather than the same one in lockstep.
	o.failures++
	o.recovering = true
	attempts := row.Attempts + 1
	step := attempts
	if verdict == verdictHoldServer {
		step++
	}
	delay := accessOutboxBackoff(step, o.jitter)
	if retryAfter > 0 {
		delay = retryAfter + o.jitter(retryAfter/5)
	}
	ev := log.Debug().Str("event_id", row.ID).Int("attempts", attempts).Dur("retry_in", delay)
	if err != nil {
		ev = ev.Err(err)
	} else {
		ev = ev.Int("status", status)
	}
	ev.Msg("Access event delivery failed; holding")

	utc := now.UTC()
	updateErr := retrySQLiteBusy(ctx, func() error {
		return o.client.AccessEventOutbox.UpdateOneID(row.ID).
			SetAttempts(attempts).
			SetNextAttemptAt(utc.Add(delay)).
			Exec(ctx)
	})
	if updateErr != nil && !ent.IsNotFound(updateErr) {
		log.Debug().Err(updateErr).Str("event_id", row.ID).Msg("Failed to reschedule held access event")
	}

	if verdict == verdictHoldEvent && o.failures < accessOutboxRowFailureStreak {
		return verdict, false
	}
	// The server is down, throttling, or failing every event: pause all
	// delivery, probing with one event per backoff.
	if verdict == verdictHoldServer {
		o.outage = true
	}
	gateDelay := accessOutboxBackoff(o.failures, o.jitter)
	o.gateFromRetry = retryAfter > 0
	if o.gateFromRetry {
		gateDelay = delay
	}
	o.gate = now.Add(gateDelay)
	return verdict, true
}

func (o *accessEventOutbox) remove(ctx context.Context, id string) {
	err := retrySQLiteBusy(ctx, func() error {
		return o.client.AccessEventOutbox.DeleteOneID(id).Exec(ctx)
	})
	if err != nil && !ent.IsNotFound(err) {
		// The row stays and is sent again; the server deduplicates.
		log.Debug().Err(err).Str("event_id", id).Msg("Failed to remove access event from the outbox")
	}
}

// releaseDeferred makes every held event due again after an outage ends.
func (o *accessEventOutbox) releaseDeferred(ctx context.Context) {
	utc := o.now().UTC()
	err := retrySQLiteBusy(ctx, func() error {
		return o.client.AccessEventOutbox.Update().
			Where(accesseventoutbox.NextAttemptAtGT(utc)).
			SetNextAttemptAt(utc).
			Exec(ctx)
	})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to release held access events")
	}
}

func (o *accessEventOutbox) purgeExpired(ctx context.Context) {
	cutoff := o.now().UTC().Add(-o.maxAge)
	var dropped int
	err := retrySQLiteBusy(ctx, func() error {
		var err error
		dropped, err = o.client.AccessEventOutbox.Delete().
			Where(accesseventoutbox.CreatedAtLT(cutoff)).
			Exec(ctx)
		return err
	})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to purge expired access events")
		return
	}
	o.noteDropped(dropped)
}

// finishRecovery logs the one Info line of a drain that followed an outage or
// a restart, once nothing more is due.
func (o *accessEventOutbox) finishRecovery() {
	if !o.recovering || o.failures > 0 {
		return
	}
	if o.recovered > 0 {
		log.Info().Int("delivered", o.recovered).Msg("Delivered held access events")
	}
	o.recovering = false
	o.recovered = 0
}

// retrySQLiteBusy retries op while SQLite reports the database or a table as
// locked, which the agent's other writers can cause for a moment.
func retrySQLiteBusy(ctx context.Context, op func() error) error {
	var err error
	for attempt := 1; ; attempt++ {
		err = op()
		if err == nil || attempt == 10 || !isSQLiteBusy(err) {
			return err
		}
		if sleepErr := sleepCtx(ctx, time.Duration(attempt)*20*time.Millisecond); sleepErr != nil {
			return err
		}
	}
}

func isSQLiteBusy(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "is locked") || strings.Contains(msg, "SQLITE_BUSY")
}
