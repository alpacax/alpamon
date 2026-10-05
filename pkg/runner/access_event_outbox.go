package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/accesseventoutbox"
	"github.com/rs/zerolog/log"
)

const (
	// accessOutboxMaxRows and accessOutboxMaxAge bound what an outage can
	// leave on disk. A row is at most a few KB (the strings are capped at the
	// server's limits), so the count bound keeps the table in the tens of MB.
	//
	// At the count bound new events are refused and the held ones kept. Anyone
	// who can log in can fill the outbox during an outage by looping logins,
	// and dropping the oldest would let them push out the first entry, which
	// is the one that has to survive; a flood instead names its own account in
	// the events that are stored. The age bound removes the oldest by age.
	//
	// The age bound reads the host clock: an event captured while the clock
	// was far behind is purged once the clock is corrected.
	accessOutboxMaxRows = 10000
	accessOutboxMaxAge  = 30 * 24 * time.Hour

	// accessOutboxInboxSize bounds events accepted from PAM but not yet
	// written. The socket handler never blocks on it: past it, an event is
	// dropped and counted.
	accessOutboxInboxSize = 1024
	// accessOutboxWriteBatch caps the events one transaction writes.
	accessOutboxWriteBatch = 256

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
	accessOutboxMaxDelay = accessOutboxMaxRetryAfter + accessOutboxMaxRetryAfter/5 +
		accessOutboxMaxBackoff + accessOutboxMaxBackoff/5

	// accessOutboxReachableJitter spreads the first drain after startup and
	// after the server becomes reachable again, so a fleet that lost the
	// server together does not drain into it together.
	accessOutboxReachableJitter = 30 * time.Second

	// accessOutboxRowFailureStreak is how many consecutive events failing
	// with a server error the drain takes as the server being down rather
	// than one event it cannot process.
	accessOutboxRowFailureStreak = 3

	// Losses are reported at most once a minute. Events dropped before they
	// were stored are gathered for a second first, so a burst is one Warn.
	accessOutboxLossWarnGap = time.Minute
	accessOutboxLossSettle  = time.Second

	// While events have been held longer than accessOutboxLongHold, one Warn
	// an hour says so, so a server that keeps refusing the agent (a revoked
	// credential, say) is not left at Debug.
	accessOutboxLongHold         = 10 * time.Minute
	accessOutboxLongHoldWarnGap  = time.Hour
	accessOutboxLongHoldCheckGap = time.Minute

	accessOutboxRestartDelay = time.Second
	accessOutboxMinWait      = 50 * time.Millisecond
	accessOutboxBatchSize    = 50
	accessOutboxPostTimeout  = 10 // seconds, the unit scheduler.Session takes
	accessOutboxStopTimeout  = 5 * time.Second
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
	// answer, a throttle, rejected agent credentials, a gateway error, or a
	// 404. Delivery pauses for every event.
	verdictHoldServer
	// verdictHoldEvent is a server error that may be about this one event.
	// Only this event backs off unless several in a row fail the same way.
	verdictHoldEvent
	verdictDrop
)

// classifyAccessDelivery maps one delivery attempt to what the outbox does
// with the event.
func classifyAccessDelivery(status int, err error) accessDeliveryVerdict {
	switch {
	case err != nil:
		return verdictHoldServer
	case status >= 200 && status < 300:
		return verdictDelivered
	// 404 is held, never dropped. Capture starts only once the server's
	// policy turns detection on, so a server without the endpoint is not a
	// real case, while a misrouted or half-deployed endpoint answering 404
	// for a while is; dropping would delete every held login in one drain.
	// The bounds limit what a server that never accepts can leave on disk.
	case status == http.StatusNotFound,
		status == http.StatusTooManyRequests,
		// 401 and 407 are about the agent's credentials or a proxy, not this
		// event; dropping on them would empty the whole backlog during an
		// auth hiccup. 403 means the server will not take the event.
		status == http.StatusUnauthorized,
		status == http.StatusProxyAuthRequired,
		status == http.StatusRequestTimeout,
		status == http.StatusTooEarly,
		status == http.StatusBadGateway,
		status == http.StatusServiceUnavailable,
		status == http.StatusGatewayTimeout:
		return verdictHoldServer
	case status >= 400 && status < 500:
		// 400, 403 and the rest: the server will not take this event however
		// often it is sent.
		return verdictDrop
	default:
		return verdictHoldEvent
	}
}

// accessResponseClass names a failed delivery for the long-hold Warn.
func accessResponseClass(status int, err error) string {
	switch {
	case err != nil:
		return "unreachable"
	case status == http.StatusUnauthorized, status == http.StatusProxyAuthRequired:
		return "unauthorized"
	case status == http.StatusNotFound:
		return "not_found"
	case status == http.StatusTooManyRequests:
		return "throttled"
	case status == http.StatusRequestTimeout, status == http.StatusTooEarly, status == http.StatusGatewayTimeout:
		return "timeout"
	case status >= 500:
		return "server_error"
	default:
		return "status_" + strconv.Itoa(status)
	}
}

// rateLimitedCount gathers a count of lost events and releases it at most
// once per accessOutboxLossWarnGap, so many losses make one Warn carrying
// their number.
type rateLimitedCount struct {
	settle time.Duration // how long a first loss waits for more

	mu           sync.Mutex
	pending      int
	firstPending time.Time
	last         time.Time
}

func (c *rateLimitedCount) add(n int, now time.Time) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == 0 {
		c.firstPending = now
	}
	c.pending += n
}

// take returns the count to report now, or zero.
func (c *rateLimitedCount) take(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == 0 || now.Sub(c.firstPending) < c.settle {
		return 0
	}
	if !c.last.IsZero() && now.Sub(c.last) < accessOutboxLossWarnGap {
		return 0
	}
	n := c.pending
	c.pending = 0
	c.last = now
	return n
}

func (c *rateLimitedCount) hasPending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pending > 0
}

// accessOutboxWrite is one item for the writer: an event, or a flush marker
// that is closed once everything queued before it is settled.
type accessOutboxWrite struct {
	event   NonAlpaconAccessEvent
	flushed chan struct{}
}

// accessEventOutbox holds login events in the agent's database until the
// server has them. Events are written before any delivery is tried, so a
// server outage, an agent restart or a shutdown delays them rather than
// losing them. One writer goroutine stores them, batching what is queued into
// one transaction, and one drain goroutine delivers them oldest first.
//
// The loss window is between the PAM ack and the insert committing: normally
// milliseconds, longer while SQLite is locked by another writer. A crash in
// it loses the queued events; so does an insert that fails outright, or a
// queue that is full. Past that, an event leaves the table only by being
// delivered, being refused by the server, or ageing out.
//
// The table comes from the agent's embedded migrations: a migration that
// fails at startup stops the agent, as any other migration does.
type accessEventOutbox struct {
	client *ent.Client
	send   accessEventSender

	// Replaced in tests.
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error
	jitter  func(limit time.Duration) time.Duration
	maxRows int
	maxAge  time.Duration

	restartDelay time.Duration

	wake      chan struct{}
	reachable chan struct{}
	done      chan struct{}

	// The writer takes events from inbox. closing asks it to write what is
	// queued and stop; abandon, cancelled when stop runs out of time, makes
	// it stop at once.
	inbox         chan accessOutboxWrite
	admitMu       sync.RWMutex
	closed        bool
	closing       chan struct{}
	closeOnce     sync.Once
	abandon       context.Context
	abandonNow    context.CancelFunc
	writerDone    chan struct{}
	startMu       sync.Mutex
	writerStarted bool
	drainStarted  bool

	refused rateLimitedCount // new events refused at the count bound
	expired rateLimitedCount // held events removed by the age bound
	lost    rateLimitedCount // events dropped before they were stored

	// Drain state, owned by the drain goroutine.
	gate           time.Time // no send before this
	gateFromRetry  bool      // the gate came from the server's Retry-After
	failures       int       // consecutive held deliveries
	outage         bool      // a server-wide failure since the last delivery
	lastSucceeded  bool      // the previous send was delivered
	lastSend       time.Time
	recovering     bool // count deliveries for the after-outage Info line
	recovered      int
	dbFailures     int
	removeFailures int
	lastClass      string // the last failed delivery, for the long-hold Warn
	lastHeldCheck  time.Time
	lastHeldWarn   time.Time
}

func newAccessEventOutbox(client *ent.Client, send accessEventSender) *accessEventOutbox {
	abandon, abandonNow := context.WithCancel(context.Background())
	return &accessEventOutbox{
		client:       client,
		send:         send,
		now:          time.Now,
		sleep:        sleepCtx,
		jitter:       randomJitter,
		maxRows:      accessOutboxMaxRows,
		maxAge:       accessOutboxMaxAge,
		restartDelay: accessOutboxRestartDelay,
		wake:         make(chan struct{}, 1),
		reachable:    make(chan struct{}, 1),
		done:         make(chan struct{}),
		inbox:        make(chan accessOutboxWrite, accessOutboxInboxSize),
		closing:      make(chan struct{}),
		abandon:      abandon,
		abandonNow:   abandonNow,
		writerDone:   make(chan struct{}),
		lost:         rateLimitedCount{settle: accessOutboxLossSettle},
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

// enqueue hands an accepted event to the writer. It runs on the auth socket
// goroutine after the PAM ack is written and the socket closed, and never
// blocks: with the queue full the event is dropped and counted. It reports
// whether the event was taken, which is false only for that drop.
func (o *accessEventOutbox) enqueue(event NonAlpaconAccessEvent) bool {
	// The read lock lets stop wait out a hand-off already under way, so the
	// writer drains it; one that comes after stop has begun cannot rely on
	// the writer and stores the event itself while the process lasts.
	taken := true
	o.admitMu.RLock()
	closed := o.closed
	if !closed {
		select {
		case o.inbox <- accessOutboxWrite{event: event}:
		default:
			taken = false
			o.lost.add(1, o.now())
			log.Debug().Str("event_id", event.EventID).Msg("Access event queue full; dropping event")
		}
	}
	o.admitMu.RUnlock()
	if closed {
		ctx, cancel := context.WithTimeout(context.Background(), accessOutboxStopTimeout)
		defer cancel()
		o.store(ctx, []NonAlpaconAccessEvent{event})
	}
	return taken
}

// flush waits until everything enqueued before it is stored or given up on.
func (o *accessEventOutbox) flush() {
	done := make(chan struct{})
	select {
	case o.inbox <- accessOutboxWrite{flushed: done}:
	case <-o.writerDone:
		return
	}
	select {
	case <-done:
	case <-o.writerDone:
	}
}

// start launches the writer and the drain. stop joins them.
func (o *accessEventOutbox) start(ctx context.Context) {
	o.startWriter()
	o.startMu.Lock()
	defer o.startMu.Unlock()
	if o.drainStarted {
		return
	}
	o.drainStarted = true
	go o.run(ctx)
}

func (o *accessEventOutbox) startWriter() {
	o.startMu.Lock()
	defer o.startMu.Unlock()
	if o.writerStarted {
		return
	}
	o.writerStarted = true
	go func() {
		defer close(o.writerDone)
		o.supervise("writer", o.abandon.Done(), o.writeLoop)
	}()
}

// stop lets the writer store what is queued and waits, up to timeout, for it
// and for the drain, whose context the caller has already cancelled. It
// reports whether both finished; on a timeout the writer is told to give up.
func (o *accessEventOutbox) stop(timeout time.Duration) bool {
	o.admitMu.Lock()
	o.closed = true
	o.admitMu.Unlock()
	o.closeOnce.Do(func() { close(o.closing) })
	defer o.abandonNow()

	o.startMu.Lock()
	var waits []<-chan struct{}
	if o.writerStarted {
		waits = append(waits, o.writerDone)
	}
	if o.drainStarted {
		waits = append(waits, o.done)
	}
	o.startMu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for _, ch := range waits {
		select {
		case <-ch:
		case <-timer.C:
			return false
		}
	}
	return true
}

// supervise runs loop until it returns, restarting it after a recovered panic
// so one bad moment cannot end delivery for the life of the agent.
func (o *accessEventOutbox) supervise(name string, stopped <-chan struct{}, loop func()) {
	for runRecovered(name, loop) {
		timer := time.NewTimer(o.restartDelay)
		select {
		case <-stopped:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// runRecovered runs loop and reports whether it panicked. The log names only
// the panic's type, never its value, which could carry event data.
func runRecovered(name string, loop func()) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			log.Error().Str("loop", name).Str("panic", describePanic(r)).
				Msg("Access event outbox loop panicked; restarting it")
		}
	}()
	loop()
	return false
}

func describePanic(r any) string {
	return fmt.Sprintf("%T", r)
}

func (o *accessEventOutbox) writeLoop() {
	for {
		// Losses gathered while the writer waits for work are reported
		// once they have settled.
		var timer *time.Timer
		var report <-chan time.Time
		if o.lost.hasPending() {
			timer = time.NewTimer(accessOutboxLossSettle)
			report = timer.C
		}
		select {
		case w := <-o.inbox:
			o.writeBatch(o.collect(w))
		case <-report:
			o.reportLosses()
		case <-o.closing:
			// Shutdown: store whatever is queued, then stop.
			for {
				select {
				case w := <-o.inbox:
					o.writeBatch(o.collect(w))
				default:
					o.reportLosses()
					return
				}
			}
		case <-o.abandon.Done():
			return
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (o *accessEventOutbox) collect(first accessOutboxWrite) []accessOutboxWrite {
	batch := []accessOutboxWrite{first}
	for len(batch) < accessOutboxWriteBatch {
		select {
		case w := <-o.inbox:
			batch = append(batch, w)
		default:
			return batch
		}
	}
	return batch
}

// writeBatch stores the events in batch and releases its flush markers,
// whatever happens to the events.
func (o *accessEventOutbox) writeBatch(batch []accessOutboxWrite) {
	defer func() {
		for _, w := range batch {
			if w.flushed != nil {
				close(w.flushed)
			}
		}
	}()
	var events []NonAlpaconAccessEvent
	for _, w := range batch {
		if w.flushed == nil {
			events = append(events, w.event)
		}
	}
	if len(events) > 0 {
		o.store(o.abandon, events)
	}
	o.reportLosses()
}

type accessOutboxRow struct {
	id        string
	payload   []byte
	createdAt time.Time
}

// store writes events in one transaction, retrying while SQLite is locked by
// another writer until the outbox is abandoned at shutdown. Events queue
// behind it meanwhile, up to accessOutboxInboxSize.
func (o *accessEventOutbox) store(ctx context.Context, events []NonAlpaconAccessEvent) {
	rows := make([]accessOutboxRow, 0, len(events))
	for _, event := range events {
		// Stored without held_seconds; that is worked out at each send.
		event.HeldSeconds = 0
		payload, err := json.Marshal(event)
		if err != nil {
			o.lost.add(1, o.now())
			continue
		}
		createdAt := event.Timestamp
		if createdAt.IsZero() {
			createdAt = o.now()
		}
		rows = append(rows, accessOutboxRow{id: event.EventID, payload: payload, createdAt: createdAt.UTC()})
	}
	if len(rows) == 0 {
		return
	}

	for attempt := 1; ; attempt++ {
		stored, refused, err := o.insertRows(ctx, rows)
		if err == nil {
			o.refused.add(refused, o.now())
			log.Debug().Int("stored", stored).Int("refused", refused).Msg("Access events stored for delivery")
			if stored > 0 {
				nudge(o.wake)
			}
			return
		}
		if !isSQLiteBusy(err) || ctx.Err() != nil {
			o.lost.add(len(rows), o.now())
			log.Debug().Err(err).Int("events", len(rows)).Msg("Failed to store access events")
			return
		}
		o.reportLosses()
		pause := min(time.Duration(attempt)*20*time.Millisecond, 100*time.Millisecond)
		if sleepCtx(ctx, pause) != nil {
			o.lost.add(len(rows), o.now())
			return
		}
	}
}

// insertRows inserts what fits under maxRows and refuses the rest; a row
// whose event_id is already held is skipped, since the server deduplicates
// on it and one row is all delivery needs.
func (o *accessEventOutbox) insertRows(ctx context.Context, rows []accessOutboxRow) (stored, refused int, err error) {
	tx, err := o.client.Tx(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	count, err := tx.AccessEventOutbox.Query().Count(ctx)
	if err != nil {
		return 0, 0, err
	}
	nextAttempt := o.now().UTC()
	for _, row := range rows {
		if count >= o.maxRows {
			refused++
			continue
		}
		insertErr := tx.AccessEventOutbox.Create().
			SetID(row.id).
			SetPayload(row.payload).
			SetCreatedAt(row.createdAt).
			SetNextAttemptAt(nextAttempt).
			Exec(ctx)
		if ent.IsConstraintError(insertErr) {
			continue
		}
		if insertErr != nil {
			return 0, 0, insertErr
		}
		count++
		stored++
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return stored, refused, nil
}

// reportLosses logs the rate-limited Warns for events that never reached,
// or left, the outbox other than by delivery.
func (o *accessEventOutbox) reportLosses() {
	now := o.now()
	if n := o.refused.take(now); n > 0 {
		log.Warn().Int("refused", n).Int("max_events", o.maxRows).
			Msg("Refused new access events: the outbox is full and keeps the earliest")
	}
	if n := o.expired.take(now); n > 0 {
		log.Warn().Int("expired", n).Str("max_age", o.maxAge.String()).
			Msg("Dropped held access events past the outbox age limit")
	}
	if n := o.lost.take(now); n > 0 {
		log.Warn().Int("dropped", n).
			Msg("Dropped access events before they were stored")
	}
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
	o.supervise("drain", ctx.Done(), func() { o.drainLoop(ctx) })
}

func (o *accessEventOutbox) drainLoop(ctx context.Context) {
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
			o.onReachable(ctx)
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

// onReachable ends a backoff early once the server is known to answer again:
// the queue's pause and every held event's own backoff, which after a long
// outage sit up to ten minutes out. A Retry-After is the server's own
// instruction and stands.
func (o *accessEventOutbox) onReachable(ctx context.Context) {
	if o.failures == 0 || o.gateFromRetry {
		return
	}
	at := o.now().Add(o.jitter(accessOutboxReachableJitter))
	if at.Before(o.gate) {
		o.gate = at
	}
	o.releaseHeldUntil(ctx, at)
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
	o.warnLongHold(ctx)
	o.reportLosses()

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
		return verdictDrop, o.settle(ctx, row.ID)
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

	verdict = classifyAccessDelivery(status, err)
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
		o.failures = 0
		o.gate = time.Time{}
		o.gateFromRetry = false
		if o.recovering {
			o.recovered++
		}
		log.Debug().Str("event_id", row.ID).Int("status", status).Int64("held_seconds", event.HeldSeconds).
			Msg("Access event delivered")
		return verdict, o.settle(ctx, row.ID)

	case verdictDrop:
		o.failures = 0
		log.Warn().Str("event_id", row.ID).Int("status", status).
			Msg("Access event rejected by server; dropping event")
		return verdict, o.settle(ctx, row.ID)
	}

	// Held. The row backs off on its own count, so an event the server keeps
	// failing on cannot hold up the ones behind it. When the whole queue
	// pauses, the row waits one step longer than the queue does, so the next
	// probe is a different event rather than the same one in lockstep.
	o.failures++
	o.lastClass = accessResponseClass(status, err)
	attempts := row.Attempts + 1
	step := attempts
	if verdict == verdictHoldServer {
		step++
	}
	delay := accessOutboxBackoff(step, o.jitter)
	retryDelay := retryAfter + o.jitter(retryAfter/5)
	if retryAfter > 0 {
		// The server's wait, plus the event's own step, so the probe after
		// the pause is still a different event.
		delay = retryDelay + accessOutboxBackoff(attempts, o.jitter)
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
		gateDelay = retryDelay
	}
	o.gate = now.Add(gateDelay)
	// Count what the drain delivers once the pause ends, for its Info line.
	o.recovering = true
	return verdict, true
}

// settle removes a row the server has answered for good. If the delete
// fails, as on a full or read-only disk, the row is still due and would be
// resent at once, so the pass ends and the drain backs off; the server
// deduplicates the resend when it comes. stop reports that the pass must end.
func (o *accessEventOutbox) settle(ctx context.Context, id string) (stop bool) {
	err := retrySQLiteBusy(ctx, func() error {
		return o.client.AccessEventOutbox.DeleteOneID(id).Exec(ctx)
	})
	if err == nil || ent.IsNotFound(err) {
		o.removeFailures = 0
		return false
	}
	o.removeFailures++
	log.Debug().Err(err).Str("event_id", id).Msg("Failed to remove access event from the outbox")
	o.gate = o.now().Add(accessOutboxBackoff(o.removeFailures, o.jitter))
	o.gateFromRetry = false
	return true
}

// releaseDeferred makes every held event due again after an outage ends.
func (o *accessEventOutbox) releaseDeferred(ctx context.Context) {
	o.releaseHeldUntil(ctx, o.now())
}

// releaseHeldUntil moves every held event whose next attempt is later than at
// to at.
func (o *accessEventOutbox) releaseHeldUntil(ctx context.Context, at time.Time) {
	utc := at.UTC()
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
	o.expired.add(dropped, o.now())
}

// warnLongHold logs, at most once an hour, how many events have been held for
// more than accessOutboxLongHold and how the last delivery failed.
func (o *accessEventOutbox) warnLongHold(ctx context.Context) {
	now := o.now()
	if !o.lastHeldWarn.IsZero() && now.Sub(o.lastHeldWarn) < accessOutboxLongHoldWarnGap {
		return
	}
	if !o.lastHeldCheck.IsZero() && now.Sub(o.lastHeldCheck) < accessOutboxLongHoldCheckGap {
		return
	}
	o.lastHeldCheck = now
	var held int
	err := retrySQLiteBusy(ctx, func() error {
		var err error
		held, err = o.client.AccessEventOutbox.Query().
			Where(accesseventoutbox.CreatedAtLT(now.UTC().Add(-accessOutboxLongHold))).
			Count(ctx)
		return err
	})
	if err != nil || held == 0 {
		return
	}
	class := o.lastClass
	if class == "" {
		class = "not_attempted"
	}
	o.lastHeldWarn = now
	log.Warn().Int("held", held).Str("last_response", class).
		Msg("Access events have been held for more than ten minutes")
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
// locked, which the agent's other writers can cause for a moment. It gives
// up after ten tries; the drain comes back to the work on its next pass.
func retrySQLiteBusy(ctx context.Context, op func() error) error {
	var err error
	for attempt := 1; ; attempt++ {
		err = op()
		if err == nil || !isSQLiteBusy(err) || attempt == 10 {
			return err
		}
		pause := min(time.Duration(attempt)*20*time.Millisecond, 100*time.Millisecond)
		if sleepErr := sleepCtx(ctx, pause); sleepErr != nil {
			return err
		}
	}
}

func isSQLiteBusy(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "is locked") || strings.Contains(msg, "SQLITE_BUSY")
}
