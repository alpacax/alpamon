//go:build linux

package exposure

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnavailableServerSkipsCollectionForDay(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: http.StatusNotFound}}}}
	reads := 0
	s := testService(p, func(context.Context) *exposureReport { reads++; return sampleReport() })
	now := s.now()
	s.now = func() time.Time { return now }
	s.readAndDeliver(context.Background())
	now = now.Add(23 * time.Hour)
	s.readAndDeliver(context.Background())
	assert.Equal(t, 1, reads)
	now = now.Add(time.Hour)
	s.readAndDeliver(context.Background())
	assert.Equal(t, 2, reads)
	assert.Len(t, p.callsTo(checkURL), 2)
}
func TestPermanentDeliveryFailuresDoNotRetry(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 413, 422} {
		p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: status, err: errors.New("body read failed")}}}}
		s := testService(p, nil)
		s.send(context.Background(), checkURL, nil, time.Second, nil)
		assert.Len(t, p.callsTo(checkURL), 1)
	}
	session := &scheduler.Session{BaseURL: "http://[invalid", Client: &http.Client{}}
	s := newService(session, nil, nil)
	sleeps := 0
	s.sleep = func(context.Context, time.Duration) bool { sleeps++; return true }
	_, ok := s.send(context.Background(), checkURL, nil, time.Second, nil)
	assert.False(t, ok)
	assert.Zero(t, sleeps)
}
func TestRetryDelaysHaveBoundedJitter(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 500}}}}
	s := testService(p, nil)
	var delays []time.Duration
	s.sleep = func(_ context.Context, d time.Duration) bool { delays = append(delays, d); return true }
	s.send(context.Background(), checkURL, nil, time.Second, nil)
	require.Len(t, delays, maxAttempts-1)
	base := firstBackoff
	varied := false
	for _, d := range delays {
		assert.GreaterOrEqual(t, d, base*8/10)
		assert.LessOrEqual(t, d, base*12/10)
		varied = varied || d != base
		base = min(base*3, maxBackoff)
	}
	assert.True(t, varied)
}

func TestUnavailableServerOversized404SkipsCollection(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 404, err: scheduler.ErrExposureResponseTooLarge}}}}
	reads := 0
	s := testService(p, func(context.Context) *exposureReport { reads++; return sampleReport() })
	s.readAndDeliver(context.Background())
	s.readAndDeliver(context.Background())
	assert.Equal(t, 1, reads)
}

func TestTriggerClearsUnavailableServerDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {
			{status: http.StatusNotFound},
			{status: http.StatusOK, body: `{"required":false}`},
		}}}
		var reads atomic.Int32
		s := testService(p, func(context.Context) *exposureReport { reads.Add(1); return sampleReport() })
		s.now = time.Now
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); s.runLoop(ctx) }()
		synctest.Wait()
		require.EqualValues(t, 1, reads.Load())

		time.Sleep(readInterval)
		synctest.Wait()
		assert.EqualValues(t, 1, reads.Load(), "timer reads honor the 24-hour delay")
		s.trigger <- struct{}{}
		synctest.Wait()
		assert.EqualValues(t, 2, reads.Load(), "a trigger collects during the delay")
		assert.Len(t, p.callsTo(checkURL), 2)

		time.Sleep(readInterval)
		synctest.Wait()
		assert.EqualValues(t, 3, reads.Load(), "the cleared delay no longer blocks timer reads")
		cancel()
		<-done
		assert.True(t, s.unavailableUntil.IsZero())
	})
}
