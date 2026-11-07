//go:build linux

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	checkURL  = "/api/servers/servers/-/exposure-check/"
	reportURL = "/api/servers/servers/-/exposure/"

	readInterval  = 3600 * time.Second
	maxReadJitter = 5 * time.Minute

	checkTimeout  = 10 * time.Second
	reportTimeout = 60 * time.Second
	maxAttempts   = 5
	firstBackoff  = 5 * time.Second
	maxBackoff    = 5 * time.Minute
	maxRespBytes  = 64 << 10
)

// Poster is the part of scheduler.Session the transport uses. These calls
// bypass the request queue: its reporter logs response bodies on failure,
// which this endpoint pair must never do.
type Poster interface {
	PostExposure(ctx context.Context, url string, body any, timeout time.Duration) ([]byte, int, http.Header, error)
}

// service serializes exposure reads and their delivery: one goroutine reads,
// checks and reports, so at most one read is in flight. A trigger that
// arrives during a read is held in a one-slot channel and causes exactly one
// more read after it.
type service struct {
	post    Poster
	collect func(ctx context.Context) *Report
	trigger chan struct{}
	now     func() time.Time
	jitter  func() time.Duration
	sleep   func(ctx context.Context, d time.Duration) bool
	// lastObserved keeps observed_at strictly increasing across reads, so a
	// second read within the same second is never taken for a replay.
	lastObserved time.Time
}

func newService(p Poster, collect func(ctx context.Context) *Report, trigger chan struct{}) *service {
	return &service{
		post:    p,
		collect: collect,
		trigger: trigger,
		now:     time.Now,
		jitter:  func() time.Duration { return rand.N(maxReadJitter) },
		sleep:   sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// run reads on its own due time, on every trigger, and once at start after
// up to maxReadJitter.
func (s *service) run(ctx context.Context) {
	timer := time.NewTimer(s.jitter())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.trigger:
		}
		s.readAndDeliver(ctx)
		timer.Reset(readInterval + s.jitter())
	}
}

// readAndDeliver reads once and delivers the result: a check, then the
// report only when the server asks for it. Retries resend the same
// observed_at and body.
func (s *service) readAndDeliver(ctx context.Context) {
	observed := s.now().UTC().Truncate(time.Second)
	if !observed.After(s.lastObserved) {
		observed = s.lastObserved.Add(time.Second)
		if !s.sleep(ctx, time.Until(observed)) {
			return
		}
	}
	s.lastObserved = observed

	r := s.collect(ctx)
	r.ObservedAt = observed.Format(time.RFC3339)
	body, err := finalize(r)
	if err != nil {
		log.Debug().Msg("Exposure report could not be encoded.")
		return
	}
	check := checkBody(r)

	var res struct {
		Required *bool `json:"required"`
	}
	status, ok := s.send(ctx, checkURL, check, checkTimeout, &res)
	switch {
	case !ok:
		return
	case status == http.StatusNotFound:
		log.Debug().Msg("Exposure check endpoint not available on this server; skipping until the next read.")
		return
	case status != http.StatusOK || res.Required == nil:
		log.Debug().Int("status_code", status).Msg("Exposure check was not accepted.")
		return
	case !*res.Required:
		return
	}
	status, ok = s.send(ctx, reportURL, body, reportTimeout, nil)
	if ok && status != http.StatusOK {
		log.Warn().Int("status_code", status).Msg("Exposure report was not accepted.")
	}
}

// checkBody is the canonical check request for a sealed report.
func checkBody(r *Report) []byte {
	b := []byte(`{"hash":`)
	b = appendJSONString(b, r.Hash)
	b = append(b, `,"observed_at":`...)
	b = appendJSONString(b, r.ObservedAt)
	b = append(b, `,"schema_version":1}`...)
	return b
}

func retryable(status int) bool {
	return status == http.StatusRequestTimeout || status >= 500
}

// send posts body, retrying transport errors and retryable statuses with
// backoff. ok is false when delivery is deferred. Neither the request nor
// the response body is logged.
func (s *service) send(ctx context.Context, url string, body []byte, timeout time.Duration, out any) (int, bool) {
	backoff := firstBackoff
	for attempt := 1; ; attempt++ {
		resp, status, _, err := s.post.PostExposure(ctx, url, body, timeout)
		if status == http.StatusTooManyRequests {
			log.Debug().Msg("Exposure delivery throttled; skipping until the next read.")
			return status, false
		}
		if err == nil && len(resp) <= maxRespBytes && !(status >= 300 && status < 400) && !retryable(status) {
			if out != nil && status == http.StatusOK {
				if len(resp) > maxRespBytes || json.NewDecoder(bytes.NewReader(resp)).Decode(out) != nil {
					log.Debug().Msg("Exposure check response could not be parsed.")
					return status, false
				}
			}
			return status, true
		}
		if attempt >= maxAttempts || ctx.Err() != nil {
			log.Debug().Int("status_code", status).Int("attempts", attempt).Msg("Exposure delivery gave up until the next read.")
			return status, false
		}
		if !s.sleep(ctx, backoff) {
			return 0, false
		}
		backoff = min(backoff*3, maxBackoff)
	}
}
