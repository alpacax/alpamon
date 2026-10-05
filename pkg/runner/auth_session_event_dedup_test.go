package runner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSessionEventRepeats_ConcurrentIntake verifies that copies of one event
// arriving at once let exactly one through, and that distinct events arriving
// at once are all let through.
func TestSessionEventRepeats_ConcurrentIntake(t *testing.T) {
	var repeats sessionEventRepeats
	var stored atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			if !repeats.isRepeat(suLoginRequest()) {
				stored.Add(1)
			}
		})
	}
	for i := range 64 {
		wg.Go(func() {
			req := suLoginRequest()
			req.PID = 900000 + i
			assert.False(t, repeats.isRepeat(req), "a distinct event must never be dropped")
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), stored.Load(), "copies of one event store exactly once")
}

// TestSessionEventRepeats_FullMapLetsEventsThrough verifies the cap: once the
// window holds the maximum, a new event is stored without being remembered,
// so its repeat passes too rather than anything being dropped.
func TestSessionEventRepeats_FullMapLetsEventsThrough(t *testing.T) {
	clock := newFakeOutboxClock()
	repeats := sessionEventRepeats{now: clock.Now}
	for i := range maxSessionEventRepeatEntries {
		req := suLoginRequest()
		req.TTY = fmt.Sprintf("/dev/pts/%d", 100+i)
		assert.False(t, repeats.isRepeat(req))
	}

	assert.False(t, repeats.isRepeat(suLoginRequest()))
	assert.False(t, repeats.isRepeat(suLoginRequest()), "an event not remembered cannot be dropped as a repeat")
	assert.Len(t, repeats.stored, maxSessionEventRepeatEntries, "the map never grows past the cap")

	clock.Advance(sessionEventRepeatWindow)
	assert.False(t, repeats.isRepeat(suLoginRequest()))
	assert.Len(t, repeats.stored, 1, "entries outside the window are swept")
	assert.True(t, repeats.isRepeat(suLoginRequest()), "with room again, repeats are dropped")
}

// TestSessionEventRepeats_ClockSetBackLetsEventThrough verifies a clock that
// reads earlier than the stored event lets the next one through.
func TestSessionEventRepeats_ClockSetBackLetsEventThrough(t *testing.T) {
	clock := newFakeOutboxClock()
	repeats := sessionEventRepeats{now: clock.Now}

	assert.False(t, repeats.isRepeat(suLoginRequest()))
	clock.Advance(-time.Second)
	assert.False(t, repeats.isRepeat(suLoginRequest()))
}
