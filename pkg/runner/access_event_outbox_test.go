package runner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/accesseventoutbox"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the outbox on a fake clock rather than in a synctest
// bubble: every step reads and writes SQLite, and a bubble does not count file
// waits as blocked.

type fakeOutboxClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeOutboxClock() *fakeOutboxClock {
	return &fakeOutboxClock{now: time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeOutboxClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeOutboxClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Sleep advances the clock instead of waiting, so pacing shows up as elapsed
// fake time.
func (c *fakeOutboxClock) Sleep(ctx context.Context, d time.Duration) error {
	c.Advance(d)
	return ctx.Err()
}

type sentAccessEvent struct {
	event NonAlpaconAccessEvent
	body  map[string]any
	at    time.Time
}

type fakeAccessEventSender struct {
	mu      sync.Mutex
	clock   *fakeOutboxClock
	sent    []sentAccessEvent
	respond func(NonAlpaconAccessEvent) (int, time.Duration, error)
}

func (s *fakeAccessEventSender) send(_ context.Context, event NonAlpaconAccessEvent) (int, time.Duration, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return 0, 0, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return 0, 0, err
	}

	s.mu.Lock()
	var at time.Time
	if s.clock != nil {
		at = s.clock.Now()
	}
	s.sent = append(s.sent, sentAccessEvent{event: event, body: body, at: at})
	respond := s.respond
	s.mu.Unlock()

	if respond == nil {
		return http.StatusCreated, 0, nil
	}
	return respond(event)
}

func (s *fakeAccessEventSender) setResponse(status int, retryAfter time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.respond = func(NonAlpaconAccessEvent) (int, time.Duration, error) { return status, retryAfter, err }
}

func (s *fakeAccessEventSender) sentIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.sent))
	for _, sent := range s.sent {
		ids = append(ids, sent.event.EventID)
	}
	return ids
}

func (s *fakeAccessEventSender) sentEvents() []sentAccessEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sentAccessEvent(nil), s.sent...)
}

var errTestUnreachable = errors.New("dial tcp: connection refused")

func openTestOutboxDB(t *testing.T, path string) *ent.Client {
	t.Helper()
	client := db.InitTestDB(path)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newTestOutbox(t *testing.T, clock *fakeOutboxClock, sender *fakeAccessEventSender) *accessEventOutbox {
	t.Helper()
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	return newTestOutboxOn(t, client, clock, sender)
}

// newTestOutboxOn builds an outbox on a fake clock with its writer running;
// the drain is driven by calling drainOnce.
func newTestOutboxOn(t *testing.T, client *ent.Client, clock *fakeOutboxClock, sender *fakeAccessEventSender) *accessEventOutbox {
	t.Helper()
	sender.clock = clock
	o := newAccessEventOutbox(client, sender.send)
	o.now = clock.Now
	o.sleep = clock.Sleep
	o.jitter = func(time.Duration) time.Duration { return 0 }
	o.startWriter()
	t.Cleanup(func() { o.stop(5 * time.Second) })
	return o
}

// put hands events to the writer and waits until they are stored.
func put(o *accessEventOutbox, events ...NonAlpaconAccessEvent) {
	for _, event := range events {
		o.enqueue(event)
	}
	o.flush()
}

// syncBuffer is a log sink that goroutines may write while a test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogsSync(t *testing.T) *syncBuffer {
	t.Helper()
	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = previousLogger
		zerolog.SetGlobalLevel(previousLevel)
	})
	buf := &syncBuffer{}
	log.Logger = zerolog.New(buf)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	return buf
}

// lockDatabase holds SQLite's write lock from a separate connection until the
// returned function is called.
func lockDatabase(t *testing.T, path string) (unlock func()) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	conn, err := raw.Conn(context.Background())
	require.NoError(t, err)
	_, err = conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE")
	require.NoError(t, err)
	var once sync.Once
	unlock = func() {
		once.Do(func() {
			_, err := conn.ExecContext(context.Background(), "COMMIT")
			assert.NoError(t, err)
			_ = conn.Close()
			_ = raw.Close()
		})
	}
	t.Cleanup(unlock)
	return unlock
}

func newTestAccessEvent(clock *fakeOutboxClock, username string) NonAlpaconAccessEvent {
	return NonAlpaconAccessEvent{
		EventID:   uuid.NewString(),
		Username:  username,
		Service:   "sshd",
		RHost:     "203.0.113.5",
		PID:       4242,
		PPID:      4241,
		Timestamp: clock.Now(),
	}
}

func outboxRows(t *testing.T, o *accessEventOutbox) []*ent.AccessEventOutbox {
	t.Helper()
	rows, err := o.client.AccessEventOutbox.Query().
		Order(ent.Asc(accesseventoutbox.FieldCreatedAt)).
		All(context.Background())
	require.NoError(t, err)
	return rows
}

func TestAccessEventOutbox_UnreachableServerHoldsEvent(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(0, 0, errTestUnreachable)

	event := newTestAccessEvent(clock, "alice")
	put(o, event)
	wait := o.drainOnce(context.Background())

	rows := outboxRows(t, o)
	require.Len(t, rows, 1, "an undeliverable event must stay on disk")
	assert.Equal(t, event.EventID, rows[0].ID)
	assert.Equal(t, 1, rows[0].Attempts)
	assert.Equal(t, clock.Now().Add(2*time.Second), rows[0].NextAttemptAt.UTC(), "the event waits a step past the queue")
	assert.Equal(t, time.Second, wait, "the queue probes again after one second")
	assert.Len(t, sender.sentIDs(), 1)
}

// TestAccessEventOutbox_AckIsNotDelayedByDelivery pins the PAM contract: the
// ack goes out before the event is stored or sent, so a server that never
// answers cannot hold up a login.
func TestAccessEventOutbox_AckIsNotDelayedByDelivery(t *testing.T) {
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	o := newAccessEventOutbox(client, func(ctx context.Context, _ NonAlpaconAccessEvent) (int, time.Duration, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return 0, 0, errTestUnreachable
	})
	o.jitter = func(time.Duration) time.Duration { return 0 }

	am := newTestAuthManager()
	am.detectLocalAccess = true
	am.outbox = o

	ctx, cancel := context.WithCancel(context.Background())
	o.start(ctx)
	t.Cleanup(func() {
		close(release)
		cancel()
		assert.True(t, o.stop(5*time.Second), "the drain goroutine must exit")
	})

	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","rhost":"203.0.113.5","pid":712345,"ppid":712340}`)
	server1, client1 := newSessionEventPipe(t)
	go am.handleSessionEvent(raw, server1)
	require.True(t, readSessionEventAck(t, client1).Received)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first event never reached the sender")
	}

	// The sender is now stuck on the first event. A second login must still be
	// acked at once and stored.
	server2, client2 := newSessionEventPipe(t)
	done := make(chan struct{})
	go func() {
		am.handleSessionEvent(raw, server2)
		close(done)
	}()
	start := time.Now()
	require.True(t, readSessionEventAck(t, client2).Received)
	assert.Less(t, time.Since(start), time.Second, "the ack must not wait on delivery")
	<-done
	o.flush()

	assert.Len(t, outboxRows(t, o), 2, "both events must be on disk while the server is unreachable")
}

func TestAccessEventOutbox_DeliversOldestFirstWithOriginalTimestamp(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	ctx := context.Background()

	sender.setResponse(0, 0, errTestUnreachable)
	first := newTestAccessEvent(clock, "alice")
	put(o, first)
	o.drainOnce(ctx)

	clock.Advance(10 * time.Second)
	second := newTestAccessEvent(clock, "bob")
	put(o, second)
	clock.Advance(5 * time.Second)

	sender.setResponse(http.StatusCreated, 0, nil)
	wait := o.drainOnce(ctx)

	assert.Equal(t, accessOutboxIdle, wait, "an empty outbox waits for the next event")
	assert.Empty(t, outboxRows(t, o), "delivered events must be deleted")

	sent := sender.sentEvents()
	require.Len(t, sent, 3, "one failed attempt, then both events")
	assert.Equal(t, []string{first.EventID, first.EventID, second.EventID}, sender.sentIDs(), "oldest first")

	assert.True(t, first.Timestamp.Equal(sent[1].event.Timestamp), "the host-recorded time must be sent unchanged")
	assert.Equal(t, first.Timestamp.Format(time.RFC3339Nano), sent[1].body["timestamp"])
	assert.EqualValues(t, 15, sent[1].body["held_seconds"])
	assert.True(t, second.Timestamp.Equal(sent[2].event.Timestamp))
	assert.EqualValues(t, 5, sent[2].body["held_seconds"])
}

func TestAccessEventOutbox_ImmediateDeliveryOmitsHeldSeconds(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)

	event := newTestAccessEvent(clock, "alice")
	put(o, event)
	o.drainOnce(context.Background())

	sent := sender.sentEvents()
	require.Len(t, sent, 1)
	assert.NotContains(t, sent[0].body, "held_seconds", "an event that was never held sends no held_seconds")
	assert.Equal(t, event.EventID, sent[0].body["event_id"])
	for _, key := range []string{"event_id", "username", "service", "rhost", "pid", "ppid", "timestamp"} {
		assert.Contains(t, sent[0].body, key)
	}
}

func TestAccessEventOutbox_RetryableResponsesBackOff(t *testing.T) {
	// A server-wide failure (no answer, 429, 503) pauses the queue for 1, 2, 4,
	// 8 seconds and puts the event itself one step further out; a 500 may be
	// about the event alone, so only the event backs off.
	serverWide := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	eventOnly := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	cases := []struct {
		name   string
		status int
		err    error
		delays []time.Duration
	}{
		{name: "transport error", err: errTestUnreachable, delays: serverWide},
		{name: "429", status: http.StatusTooManyRequests, delays: serverWide},
		{name: "401", status: http.StatusUnauthorized, delays: serverWide},
		{name: "500", status: http.StatusInternalServerError, delays: eventOnly},
		{name: "503", status: http.StatusServiceUnavailable, delays: serverWide},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeOutboxClock()
			sender := &fakeAccessEventSender{}
			o := newTestOutbox(t, clock, sender)
			sender.setResponse(tc.status, 0, tc.err)
			ctx := context.Background()

			put(o, newTestAccessEvent(clock, "alice"))
			for attempt, want := range tc.delays {
				before := clock.Now()
				o.drainOnce(ctx)
				rows := outboxRows(t, o)
				require.Len(t, rows, 1, "a retryable response must keep the event")
				assert.Equal(t, attempt+1, rows[0].Attempts)
				assert.Equal(t, before.Add(want), rows[0].NextAttemptAt.UTC(), "attempt %d", attempt+1)

				// Not yet due: nothing is sent before the backoff ends.
				clock.Advance(want - time.Millisecond)
				o.drainOnce(ctx)
				assert.Len(t, sender.sentIDs(), attempt+1, "no send before the backoff ends")
				clock.Advance(time.Millisecond)
			}
		})
	}
}

func TestAccessEventOutbox_HonorsRetryAfter(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(http.StatusTooManyRequests, 42*time.Second, nil)

	put(o, newTestAccessEvent(clock, "alice"))
	wait := o.drainOnce(context.Background())

	rows := outboxRows(t, o)
	require.Len(t, rows, 1)
	assert.Equal(t, clock.Now().Add(43*time.Second), rows[0].NextAttemptAt.UTC(),
		"the event waits out Retry-After plus its own step")
	assert.Equal(t, 42*time.Second, wait, "the queue waits out Retry-After")
}

func TestAccessOutboxBackoff_CapsAtTenMinutes(t *testing.T) {
	noJitter := func(time.Duration) time.Duration { return 0 }
	assert.Equal(t, time.Second, accessOutboxBackoff(1, noJitter))
	assert.Equal(t, 8*time.Second, accessOutboxBackoff(4, noJitter))
	assert.Equal(t, 10*time.Minute, accessOutboxBackoff(11, noJitter))
	assert.Equal(t, 10*time.Minute, accessOutboxBackoff(1000, noJitter), "a long-failing event must not overflow")

	maxJitter := func(d time.Duration) time.Duration { return d }
	assert.LessOrEqual(t, accessOutboxBackoff(1000, maxJitter), 12*time.Minute, "jitter is bounded")
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, 120*time.Second, parseRetryAfter("120", now))
	assert.Equal(t, 30*time.Second, parseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now))
	assert.Zero(t, parseRetryAfter("", now))
	assert.Zero(t, parseRetryAfter("soon", now))
	assert.Zero(t, parseRetryAfter("-5", now))
	assert.Zero(t, parseRetryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now))
	assert.Equal(t, accessOutboxMaxRetryAfter, parseRetryAfter("86400", now), "a huge value must not stall the outbox for a day")
}

func TestAccessEventOutbox_RejectionDropsWithOneWarn(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			clock := newFakeOutboxClock()
			sender := &fakeAccessEventSender{}
			o := newTestOutbox(t, clock, sender)
			logs := captureLogs(t)
			sender.setResponse(status, 0, nil)

			event := newTestAccessEvent(clock, "alice")
			put(o, event)
			o.drainOnce(context.Background())

			assert.Empty(t, outboxRows(t, o), "a rejected event must be dropped")
			assert.Len(t, sender.sentIDs(), 1, "a rejected event must not be retried")

			lines := nonEmptyLines(logs.String())
			require.Len(t, lines, 1, "exactly one log line at Info or above: %q", logs.String())
			assert.Contains(t, lines[0], `"level":"warn"`)
			assert.Contains(t, lines[0], event.EventID)
			assert.Contains(t, lines[0], `"status":`)
			assert.NotContains(t, lines[0], "alice", "usernames stay out of Warn logs")
			assert.NotContains(t, lines[0], "203.0.113.5", "source addresses stay out of Warn logs")
		})
	}
}

// TestAccessEventOutbox_404HoldsAcrossARestart pins that a 404 never deletes
// held events: it pauses the queue like a gateway error, a restart changes
// nothing, and the backlog drains once the endpoint answers.
func TestAccessEventOutbox_404HoldsAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	sender.setResponse(http.StatusNotFound, 0, nil)
	ctx := context.Background()

	firstClient := db.InitTestDB(path)
	before := newTestOutboxOn(t, firstClient, clock, sender)
	var ids []string
	for range 20 {
		clock.Advance(time.Second)
		event := newTestAccessEvent(clock, "alice")
		ids = append(ids, event.EventID)
		put(before, event)
	}
	wait := before.drainOnce(ctx)
	assert.Len(t, sender.sentIDs(), 1, "a 404 pauses the queue after one probe")
	assert.Positive(t, wait)
	assert.Len(t, outboxRows(t, before), 20, "a 404 loses nothing")
	require.True(t, before.stop(5*time.Second))
	require.NoError(t, firstClient.Close())

	// Restarted, still answered with 404.
	clock.Advance(time.Minute)
	after := newTestOutboxOn(t, openTestOutboxDB(t, path), clock, sender)
	after.drainOnce(ctx)
	assert.Len(t, sender.sentIDs(), 2, "the restarted agent probes once and pauses again")
	assert.Len(t, outboxRows(t, after), 20, "a restart does not turn a 404 into a drop")

	sender.setResponse(http.StatusCreated, 0, nil)
	clock.Advance(time.Hour)
	after.drainOnce(ctx)
	assert.Empty(t, outboxRows(t, after), "the backlog drains once the endpoint answers")
	sent := sender.sentIDs()
	assert.Equal(t, ids[1:], sent[len(sent)-19:], "the rest go oldest first after the probe")
}

func TestAccessEventOutbox_RestartDrainsHeldEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	clock := newFakeOutboxClock()

	// First run: the server is down and two events are captured.
	firstClient := db.InitTestDB(path)
	down := &fakeAccessEventSender{}
	down.setResponse(0, 0, errTestUnreachable)
	before := newTestOutboxOn(t, firstClient, clock, down)
	events := []NonAlpaconAccessEvent{newTestAccessEvent(clock, "alice")}
	put(before, events[0])
	clock.Advance(time.Second)
	events = append(events, newTestAccessEvent(clock, "bob"))
	put(before, events[1])
	before.drainOnce(context.Background())
	require.True(t, before.stop(5*time.Second))
	require.NoError(t, firstClient.Close())

	// Second run over the same file, with the server back.
	clock.Advance(time.Hour)
	up := &fakeAccessEventSender{}
	after := newTestOutboxOn(t, openTestOutboxDB(t, path), clock, up)
	ctx, cancel := context.WithCancel(context.Background())
	after.start(ctx)
	defer func() {
		cancel()
		assert.True(t, after.stop(5*time.Second), "the drain goroutine must exit")
	}()

	require.Eventually(t, func() bool { return len(up.sentIDs()) == 2 }, 5*time.Second, 10*time.Millisecond,
		"held events must be delivered on startup")
	assert.Equal(t, []string{events[0].EventID, events[1].EventID}, up.sentIDs(), "oldest first")
	require.Eventually(t, func() bool { return len(outboxRows(t, after)) == 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestAccessEventOutbox_DuplicateEventIDStoredAndSentOnce(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(0, 0, errTestUnreachable)

	event := newTestAccessEvent(clock, "alice")
	put(o, event)
	put(o, event)
	assert.Len(t, outboxRows(t, o), 1, "one row per event id")

	sender.setResponse(http.StatusCreated, 0, nil)
	o.drainOnce(context.Background())
	assert.Equal(t, []string{event.EventID}, sender.sentIDs(), "one delivery per event id")
}

// TestAccessEventOutbox_CapKeepsTheEarliestEvents pins the cap policy: once
// full, new events are refused and the earliest held ones kept, so a flood of
// logins cannot push out the first entry.
func TestAccessEventOutbox_CapKeepsTheEarliestEvents(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	// Captured after the database exists, so migration logs stay out.
	logs := captureLogs(t)
	o.maxRows = 3

	var first []string
	for range 3 {
		clock.Advance(time.Second)
		event := newTestAccessEvent(clock, "alice")
		first = append(first, event.EventID)
		put(o, event)
	}
	clock.Advance(time.Second)
	put(o, newTestAccessEvent(clock, "mallory"), newTestAccessEvent(clock, "mallory"))

	rows := outboxRows(t, o)
	require.Len(t, rows, 3)
	assert.Equal(t, first, []string{rows[0].ID, rows[1].ID, rows[2].ID}, "the earliest events are kept")

	warns := nonEmptyLines(logs.String())
	require.Len(t, warns, 1, "one Warn for the refused events: %q", logs.String())
	assert.Contains(t, warns[0], `"refused":2`)

	// Within the minute: counted, not logged.
	put(o, newTestAccessEvent(clock, "mallory"))
	assert.Len(t, nonEmptyLines(logs.String()), 1)

	clock.Advance(time.Minute)
	put(o, newTestAccessEvent(clock, "mallory"))
	warns = nonEmptyLines(logs.String())
	require.Len(t, warns, 2)
	assert.Contains(t, warns[1], `"refused":2`, "the next Warn carries the refusals it held back")
	assert.NotContains(t, logs.String(), "mallory")
	assert.Len(t, outboxRows(t, o), 3)
}

func TestAccessEventOutbox_CapsByAge(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(0, 0, errTestUnreachable)
	ctx := context.Background()

	stale := newTestAccessEvent(clock, "alice")
	put(o, stale)
	o.drainOnce(ctx)

	clock.Advance(30*24*time.Hour + time.Second)
	fresh := newTestAccessEvent(clock, "bob")
	put(o, fresh)
	sender.setResponse(http.StatusCreated, 0, nil)
	o.drainOnce(ctx)

	assert.Empty(t, outboxRows(t, o))
	ids := sender.sentIDs()
	assert.Equal(t, []string{stale.EventID, fresh.EventID}, ids, "the stale event is purged, never re-sent")
}

func TestAccessEventOutbox_RateLimitsToFivePerSecond(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)

	for range 6 {
		put(o, newTestAccessEvent(clock, "alice"))
	}
	start := clock.Now()
	o.drainOnce(context.Background())

	sent := sender.sentEvents()
	require.Len(t, sent, 6)
	for i := 1; i < len(sent); i++ {
		assert.GreaterOrEqual(t, sent[i].at.Sub(sent[i-1].at), 200*time.Millisecond, "send %d came too soon", i)
	}
	assert.GreaterOrEqual(t, sent[5].at.Sub(start), time.Second, "six sends span at least one second")
}

func TestAccessEventOutbox_PoisonEventDoesNotBlockTheQueue(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)

	poison := newTestAccessEvent(clock, "alice")
	put(o, poison)
	var good []NonAlpaconAccessEvent
	for _, username := range []string{"bob", "carol"} {
		clock.Advance(time.Second)
		event := newTestAccessEvent(clock, username)
		good = append(good, event)
		put(o, event)
	}
	sender.respond = func(event NonAlpaconAccessEvent) (int, time.Duration, error) {
		if event.EventID == poison.EventID {
			return http.StatusInternalServerError, 0, nil
		}
		return http.StatusCreated, 0, nil
	}
	logs := captureLogs(t)

	o.drainOnce(context.Background())

	rows := outboxRows(t, o)
	require.Len(t, rows, 1, "only the failing event stays")
	assert.Equal(t, poison.EventID, rows[0].ID)
	assert.Equal(t, []string{poison.EventID, good[0].EventID, good[1].EventID}, sender.sentIDs())
	assert.Empty(t, nonEmptyLines(logs.String()), "one failing event is not an outage worth an Info line")
}

// TestAccessEventOutbox_DropResetsTheFailureStreak checks that the streak
// which pauses the queue counts consecutive held deliveries only: a rejected
// event in between ends it.
func TestAccessEventOutbox_DropResetsTheFailureStreak(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)

	statuses := []int{
		http.StatusInternalServerError,
		http.StatusInternalServerError,
		http.StatusBadRequest,
		http.StatusInternalServerError,
		http.StatusCreated,
	}
	byID := map[string]int{}
	var last string
	for _, status := range statuses {
		clock.Advance(time.Second)
		event := newTestAccessEvent(clock, "alice")
		byID[event.EventID] = status
		last = event.EventID
		put(o, event)
	}
	sender.respond = func(event NonAlpaconAccessEvent) (int, time.Duration, error) {
		return byID[event.EventID], 0, nil
	}

	o.drainOnce(context.Background())

	ids := sender.sentIDs()
	require.Len(t, ids, 5, "the 400 ends the streak, so the queue never pauses")
	assert.Equal(t, last, ids[4])
}

// TestAccessEventOutbox_FailedDeleteDoesNotResendInALoop covers a disk that
// refuses deletes: a delivered row that cannot be removed is still due, and
// must not be sent again at the full pace.
func TestAccessEventOutbox_FailedDeleteDoesNotResendInALoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutboxOn(t, openTestOutboxDB(t, path), clock, sender)

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	_, err = raw.Exec("CREATE TRIGGER refuse_delete BEFORE DELETE ON access_event_outbox BEGIN SELECT RAISE(ABORT, 'disk is read-only'); END")
	require.NoError(t, err)

	put(o, newTestAccessEvent(clock, "alice"))
	wait := o.drainOnce(context.Background())

	assert.Len(t, sender.sentIDs(), 1, "one send, then the drain backs off")
	assert.GreaterOrEqual(t, wait, time.Second)
	assert.Len(t, outboxRows(t, o), 1)

	clock.Advance(wait)
	o.drainOnce(context.Background())
	assert.Len(t, sender.sentIDs(), 2, "retried once per backoff")
}

// TestAccessEventOutbox_ServerErrorOnOneEventDoesNotStallTheQueue covers an
// event that keeps drawing a gateway error while the events behind it go
// through: it backs off alone instead of pausing the queue on every retry.
func TestAccessEventOutbox_ServerErrorOnOneEventDoesNotStallTheQueue(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	ctx := context.Background()

	poison := newTestAccessEvent(clock, "alice")
	put(o, poison)
	var good []string
	for range 3 {
		clock.Advance(time.Second)
		event := newTestAccessEvent(clock, "bob")
		good = append(good, event.EventID)
		put(o, event)
	}
	sender.respond = func(event NonAlpaconAccessEvent) (int, time.Duration, error) {
		if event.EventID == poison.EventID {
			return http.StatusServiceUnavailable, 0, nil
		}
		return http.StatusCreated, 0, nil
	}

	// The first 503 looks like an outage and pauses the queue.
	o.drainOnce(ctx)
	require.Len(t, outboxRows(t, o), 4)

	// Once the pause ends, another event probes and goes through; the
	// poisoned one fails again on its own and the rest drain behind it.
	clock.Advance(time.Second)
	o.drainOnce(ctx)

	rows := outboxRows(t, o)
	require.Len(t, rows, 1, "everything but the failing event is delivered")
	assert.Equal(t, poison.EventID, rows[0].ID)
	assert.Equal(t, 2, rows[0].Attempts)
	ids := sender.sentIDs()
	assert.Equal(t, 2, countOf(ids, poison.EventID), "the failing event is not retried on every delivery")
	for _, id := range good {
		assert.Equal(t, 1, countOf(ids, id))
	}
}

func countOf(ids []string, id string) int {
	n := 0
	for _, candidate := range ids {
		if candidate == id {
			n++
		}
	}
	return n
}

func TestAccessEventOutbox_ClockSetBackDoesNotStrandEvents(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(0, 0, errTestUnreachable)
	ctx := context.Background()

	event := newTestAccessEvent(clock, "alice")
	put(o, event)
	o.drainOnce(ctx)

	// The host clock is set back a day. The row's next attempt now looks a day
	// away, which no backoff could have produced.
	clock.Advance(-24 * time.Hour)
	sender.setResponse(http.StatusCreated, 0, nil)
	o.drainOnce(ctx)

	assert.Empty(t, outboxRows(t, o), "a clock set back must not strand held events")
	sent := sender.sentEvents()
	require.Len(t, sent, 2)
	assert.NotContains(t, sent[1].body, "held_seconds", "a negative hold is never sent")
}

func TestAccessEventOutbox_DetectionOffStopsCaptureButDeliversHeld(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(0, 0, errTestUnreachable)

	am := newTestAuthManager()
	am.outbox = o
	am.UpdateDetectLocalAccess(true)

	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","pid":712345,"ppid":712340}`)
	handle := func() {
		server, client := newSessionEventPipe(t)
		done := make(chan struct{})
		go func() {
			am.handleSessionEvent(raw, server)
			close(done)
		}()
		require.True(t, readSessionEventAck(t, client).Received)
		<-done
		o.flush()
	}

	handle()
	o.drainOnce(context.Background())
	held := outboxRows(t, o)
	require.Len(t, held, 1, "captured while detection was on")

	am.UpdateDetectLocalAccess(false)
	handle()
	assert.Len(t, outboxRows(t, o), 1, "no capture while detection is off")

	clock.Advance(time.Minute)
	sender.setResponse(http.StatusCreated, 0, nil)
	o.drainOnce(context.Background())
	assert.Empty(t, outboxRows(t, o), "the held event is still delivered")
	ids := sender.sentIDs()
	assert.Equal(t, held[0].ID, ids[len(ids)-1])
}

func TestAccessEventOutbox_LogsOneInfoAfterAnOutage(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	// Captured after the database exists, so migration logs stay out.
	logs := captureLogs(t)
	sender.setResponse(0, 0, errTestUnreachable)
	ctx := context.Background()

	for range 3 {
		put(o, newTestAccessEvent(clock, "alice"))
	}
	o.drainOnce(ctx)
	clock.Advance(time.Minute)
	sender.setResponse(http.StatusCreated, 0, nil)
	o.drainOnce(ctx)

	lines := nonEmptyLines(logs.String())
	require.Len(t, lines, 1, "one Info line per drain: %q", logs.String())
	assert.Contains(t, lines[0], `"level":"info"`)
	assert.Contains(t, lines[0], `"delivered":3`)
	assert.NotContains(t, lines[0], "alice")

	// A healthy delivery afterwards logs nothing at Info.
	put(o, newTestAccessEvent(clock, "alice"))
	o.drainOnce(ctx)
	assert.Len(t, nonEmptyLines(logs.String()), 1)
}

func TestAccessEventOutbox_ReachableShortensTheBackoff(t *testing.T) {
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	sender := &fakeAccessEventSender{}
	o := newAccessEventOutbox(client, sender.send)
	o.jitter = func(time.Duration) time.Duration { return 0 }

	// The state a long outage leaves: the queue paused and the held event
	// itself ten minutes out after many failed attempts.
	now := time.Now()
	event := newTestAccessEvent(newFakeOutboxClock(), "alice")
	event.Timestamp = now.Add(-time.Hour)
	payload, err := json.Marshal(event)
	require.NoError(t, err)
	require.NoError(t, client.AccessEventOutbox.Create().
		SetID(event.EventID).
		SetPayload(payload).
		SetCreatedAt(event.Timestamp.UTC()).
		SetAttempts(12).
		SetNextAttemptAt(now.Add(10*time.Minute).UTC()).
		Exec(context.Background()))
	o.failures = 12

	ctx, cancel := context.WithCancel(context.Background())
	o.start(ctx)
	defer func() {
		cancel()
		assert.True(t, o.stop(5*time.Second), "the drain goroutine must exit")
	}()

	o.notifyReachable()

	require.Eventually(t, func() bool { return len(outboxRows(t, o)) == 0 }, 5*time.Second, 10*time.Millisecond,
		"connectivity returning must not wait out a ten-minute backoff")
	assert.Equal(t, []string{event.EventID}, sender.sentIDs())
}

// TestAccessEventOutbox_StopJoinsTheDrain is the goroutine-leak check: stop
// returns true only once the drain goroutine has exited, even while a send is
// in flight.
func TestAccessEventOutbox_StopJoinsTheDrain(t *testing.T) {
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	entered := make(chan struct{}, 1)
	o := newAccessEventOutbox(client, func(ctx context.Context, _ NonAlpaconAccessEvent) (int, time.Duration, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return 0, 0, ctx.Err()
	})
	o.jitter = func(time.Duration) time.Duration { return 0 }

	ctx, cancel := context.WithCancel(context.Background())
	o.start(ctx)
	event := newTestAccessEvent(newFakeOutboxClock(), "alice")
	event.Timestamp = time.Now()
	put(o, event)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the event never reached the sender")
	}

	cancel()
	require.True(t, o.stop(5*time.Second), "stop must join the drain goroutine")

	rows := outboxRows(t, o)
	require.Len(t, rows, 1, "an event cut off by shutdown stays on disk")
	assert.Zero(t, rows[0].Attempts, "a send cut off by shutdown is not counted as a failure")
}

func TestAccessEventOutbox_PostsThroughTheSession(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, nonAlpaconAccessEventURL, r.URL.Path)
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	am := newTestAuthManager()
	am.session = &scheduler.Session{BaseURL: srv.URL, Client: srv.Client()}
	event := newTestAccessEvent(newFakeOutboxClock(), "alice")
	event.HeldSeconds = 9

	status, retryAfter, err := am.postAccessEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.Equal(t, 17*time.Second, retryAfter)
	assert.Equal(t, event.EventID, gotBody["event_id"])
	assert.EqualValues(t, 9, gotBody["held_seconds"])
}

func nonEmptyLines(s string) []string {
	var lines []string
	for line := range strings.SplitSeq(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestAccessEventOutbox_BurstWhileTheDatabaseIsLockedLosesNothing sends a
// burst of concurrent logins while another connection holds SQLite's write
// lock: every ack stays fast, and every event is stored once the lock lifts.
func TestAccessEventOutbox_BurstWhileTheDatabaseIsLockedLosesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	clock := newFakeOutboxClock()
	o := newTestOutboxOn(t, openTestOutboxDB(t, path), clock, &fakeAccessEventSender{})
	am := newTestAuthManager()
	am.detectLocalAccess = true
	am.outbox = o
	logs := captureLogsSync(t)

	unlock := lockDatabase(t, path)

	const logins = 300
	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","pid":712345,"ppid":712340}`)
	latencies := make(chan time.Duration, logins)
	var wg sync.WaitGroup
	for range logins {
		wg.Add(1)
		go func() {
			defer wg.Done()
			server, client := newSessionEventPipe(t)
			start := time.Now()
			go am.handleSessionEvent(raw, server)
			resp := readSessionEventAck(t, client)
			latencies <- time.Since(start)
			assert.True(t, resp.Received)
		}()
	}
	wg.Wait()
	close(latencies)
	var slowest time.Duration
	for latency := range latencies {
		slowest = max(slowest, latency)
	}
	assert.Less(t, slowest, 250*time.Millisecond, "an ack must not wait on the locked database")

	time.Sleep(2 * time.Second) // hold the lock while the writer retries
	unlock()
	o.flush()

	assert.Len(t, outboxRows(t, o), logins, "nothing within the queue bound is lost")
	assert.Empty(t, nonEmptyLines(logs.String()), "no loss to report")
}

// TestAccessEventOutbox_QueueOverflowIsCountedInOneWarn fills a small queue
// while the writer is stuck on a locked database: the overflow is dropped
// without blocking and reported once with its count.
func TestAccessEventOutbox_QueueOverflowIsCountedInOneWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	client := openTestOutboxDB(t, path)
	o := newAccessEventOutbox(client, (&fakeAccessEventSender{}).send)
	o.inbox = make(chan accessOutboxWrite, 4)
	logs := captureLogsSync(t)

	unlock := lockDatabase(t, path)
	o.startWriter()
	t.Cleanup(func() { o.stop(5 * time.Second) })

	const sent = 20
	clock := newFakeOutboxClock()
	for range sent {
		o.enqueue(newTestAccessEvent(clock, "alice"))
		time.Sleep(time.Millisecond)
	}

	// The driver waits out a lock for a few seconds per attempt, so the
	// report comes after the writer's first attempt gives up.
	require.Eventually(t, func() bool { return len(nonEmptyLines(logs.String())) > 0 }, 15*time.Second, 20*time.Millisecond,
		"the overflow is reported while the writer is still stuck")
	unlock()
	o.flush()

	lines := nonEmptyLines(logs.String())
	require.Len(t, lines, 1, "one Warn for the whole overflow: %q", logs.String())
	var entry struct {
		Level   string `json:"level"`
		Dropped int    `json:"dropped"`
	}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	assert.Equal(t, "warn", entry.Level)
	assert.Positive(t, entry.Dropped)
	assert.Equal(t, sent, entry.Dropped+len(outboxRows(t, o)), "every event is either stored or counted")
	assert.NotContains(t, lines[0], "alice")
}

// TestAccessEventOutbox_StopStoresWhatIsQueued checks shutdown: events
// accepted before stop reach the disk.
func TestAccessEventOutbox_StopStoresWhatIsQueued(t *testing.T) {
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	o := newAccessEventOutbox(client, (&fakeAccessEventSender{}).send)
	o.startWriter()

	clock := newFakeOutboxClock()
	for range 50 {
		o.enqueue(newTestAccessEvent(clock, "alice"))
	}
	require.True(t, o.stop(5*time.Second), "the writer must finish within the budget")
	assert.Len(t, outboxRows(t, o), 50)
}

// TestAccessEventOutbox_LongHoldWarnsOnceAnHour covers a server that keeps
// refusing the agent: the held events surface at Warn, once an hour, with
// the count and the kind of failure and nothing about the logins.
func TestAccessEventOutbox_LongHoldWarnsOnceAnHour(t *testing.T) {
	clock := newFakeOutboxClock()
	sender := &fakeAccessEventSender{}
	o := newTestOutbox(t, clock, sender)
	sender.setResponse(http.StatusUnauthorized, 0, nil)
	logs := captureLogs(t)
	ctx := context.Background()

	put(o, newTestAccessEvent(clock, "alice"), newTestAccessEvent(clock, "alice"))
	o.drainOnce(ctx)
	assert.Empty(t, nonEmptyLines(logs.String()), "a short hold stays at Debug")

	clock.Advance(11 * time.Minute)
	o.drainOnce(ctx)
	lines := nonEmptyLines(logs.String())
	require.Len(t, lines, 1, "%q", logs.String())
	assert.Contains(t, lines[0], `"level":"warn"`)
	assert.Contains(t, lines[0], `"held":2`)
	assert.Contains(t, lines[0], `"last_response":"unauthorized"`)
	assert.NotContains(t, lines[0], "alice")
	assert.NotContains(t, lines[0], "203.0.113.5")

	clock.Advance(30 * time.Minute)
	o.drainOnce(ctx)
	assert.Len(t, nonEmptyLines(logs.String()), 1, "at most once an hour")

	clock.Advance(31 * time.Minute)
	o.drainOnce(ctx)
	assert.Len(t, nonEmptyLines(logs.String()), 2)
}

// TestAccessEventOutbox_DrainComesBackAfterAPanic injects a panic into a
// send: the drain logs it once at Error, without event data, and restarts.
func TestAccessEventOutbox_DrainComesBackAfterAPanic(t *testing.T) {
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	var mu sync.Mutex
	calls := 0
	o := newAccessEventOutbox(client, func(_ context.Context, event NonAlpaconAccessEvent) (int, time.Duration, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			panic(fmt.Errorf("send failed for %s", event.Username))
		}
		return http.StatusCreated, 0, nil
	})
	o.jitter = func(time.Duration) time.Duration { return 0 }
	o.restartDelay = 10 * time.Millisecond
	logs := captureLogsSync(t)

	ctx, cancel := context.WithCancel(context.Background())
	o.start(ctx)
	event := newTestAccessEvent(newFakeOutboxClock(), "alice")
	event.Timestamp = time.Now()
	o.enqueue(event)

	require.Eventually(t, func() bool {
		mu.Lock()
		sent := calls
		mu.Unlock()
		return sent >= 2 && len(outboxRows(t, o)) == 0
	}, 5*time.Second, 10*time.Millisecond, "the restarted drain delivers the event")
	cancel()
	require.True(t, o.stop(5*time.Second), "the supervised drain still exits on stop")

	var errorLines []string
	for _, line := range nonEmptyLines(logs.String()) {
		if strings.Contains(line, `"level":"error"`) {
			errorLines = append(errorLines, line)
		}
	}
	require.Len(t, errorLines, 1, "the panic is logged once: %q", logs.String())
	assert.Contains(t, errorLines[0], `"loop":"drain"`)
	assert.NotContains(t, logs.String(), "alice", "the panic value is not logged")
}

// TestAccessEventOutbox_HandOffAfterStopIsStillStored covers a socket handler
// that reaches the outbox only after shutdown began: the writer is gone, so
// the event is stored directly.
func TestAccessEventOutbox_HandOffAfterStopIsStillStored(t *testing.T) {
	client := openTestOutboxDB(t, filepath.Join(t.TempDir(), "outbox.db"))
	o := newAccessEventOutbox(client, (&fakeAccessEventSender{}).send)
	o.startWriter()
	require.True(t, o.stop(5*time.Second))

	o.enqueue(newTestAccessEvent(newFakeOutboxClock(), "alice"))
	assert.Len(t, outboxRows(t, o), 1)
}
