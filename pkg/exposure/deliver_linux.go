//go:build linux

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

const (
	checkURL  = "/api/servers/servers/-/exposure-check/"
	reportURL = "/api/servers/servers/-/exposure/"

	readInterval     = 3600 * time.Second
	maxReadJitter    = 5 * time.Minute
	loopRestartPause = 60 * time.Second

	checkTimeout  = 10 * time.Second
	reportTimeout = 60 * time.Second
	maxAttempts   = 5
	firstBackoff  = 5 * time.Second
	maxBackoff    = 5 * time.Minute
)

// service serializes exposure reads and their delivery. A trigger that
// arrives during a read is held in a one-slot channel and causes exactly one
// more read after it.
type service struct {
	post    Poster
	collect func(ctx context.Context) *exposureReport
	trigger chan struct{}
	now     func() time.Time
	jitter  func() time.Duration
	sleep   func(ctx context.Context, d time.Duration) bool
	// lastObserved keeps observed_at strictly increasing across reads, so a
	// second read within the same second is never taken for a replay.
	lastObserved     time.Time
	due              time.Time
	unavailableUntil time.Time
}

func newService(p Poster, collect func(ctx context.Context) *exposureReport, trigger chan struct{}) *service {
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
	for ctx.Err() == nil {
		if !s.runLoop(ctx) || !sleepCtx(ctx, loopRestartPause) {
			return
		}
	}
}

// runLoop returns true only after a panic. due lives on the service so a
// restart neither loses an upcoming read nor adds jitter to its deadline.
func (s *service) runLoop(ctx context.Context) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
			logExposurePanic("service", "Exposure service loop panicked; restarting after 60 seconds.")
		}
	}()
	if s.due.IsZero() {
		s.due = s.now().Add(s.jitter())
	}
	timer := time.NewTimer(s.due.Sub(s.now()))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			s.due = s.now().Add(readInterval + s.jitter())
		case <-s.trigger:
			s.unavailableUntil = time.Time{}
		}
		s.readAndDeliver(ctx)
		timer.Reset(s.due.Sub(s.now()))
	}
}

// readAndDeliver reads once and delivers the result: a check, then the
// report only when the server asks for it. Retries resend the same
// observed_at and body.
func (s *service) readAndDeliver(ctx context.Context) {
	if s.now().Before(s.unavailableUntil) {
		return
	}
	r, body := s.buildReport(ctx)
	if r == nil {
		return
	}
	check := checkBody(r)

	var res struct {
		Required *bool `json:"required"`
	}
	status, ok := s.send(ctx, checkURL, check, checkTimeout, &res)
	switch {
	case status == http.StatusNotFound:
		s.unavailableUntil = s.now().Add(24 * time.Hour)
		log.Debug().Msg("Exposure check endpoint not available on this server; skipping for 24 hours.")
		return
	case !ok:
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

func (s *service) buildReport(ctx context.Context) (report *exposureReport, encoded []byte) {
	stage := "collect"
	var observed time.Time
	defer func() {
		if recover() != nil {
			// Capture the original frame while its panic is still on the
			// stack. The fallback has its own boundary and bypasses all
			// collection, assembly and cap code, including their hooks.
			stage, location := exposurePanicDetails(stage)
			var fallbackSource string
			report, encoded, fallbackSource = fallbackReport(observed)
			message := "Exposure read panicked; recovered at read boundary."
			if fallbackSource != "" {
				stage, location = "fallback", fallbackSource
				message = "Exposure fallback builder panicked; skipping until the next read."
			}
			logExposurePanicAt(stage, location, message)
		}
	}()
	observed = s.now().UTC().Truncate(time.Second)
	if !observed.After(s.lastObserved) {
		if s.lastObserved.Sub(observed) > 2*time.Second {
			log.Warn().Msg("Exposure observed a backward clock step.")
		} else {
			observed = s.lastObserved.Add(time.Second)
			if !s.sleep(ctx, observed.Sub(s.now())) {
				return nil, nil
			}
		}
	}
	s.lastObserved = observed

	r := s.collect(ctx)
	r.ObservedAt = observed.Format(time.RFC3339)
	stage = "finalize"
	body, err := finalize(r)
	if err != nil {
		log.Debug().Msg("Exposure report could not be encoded.")
		return nil, nil
	}
	if len(body) > maxReportBytes {
		log.Debug().Msg("Exposure report exceeds the byte limit; skipping until the next read.")
		return nil, nil
	}
	return r, body
}

func fallbackReport(observed time.Time) (report *exposureReport, encoded []byte, panicSource string) {
	defer func() {
		if recover() != nil {
			report, encoded = nil, nil
			panicSource = exposurePanicSource()
		}
	}()
	readHook("fallback")
	// The contract requires an sshd object. Use its empty policy form.
	r := &exposureReport{
		SchemaVersion: schemaVersion,
		ObservedAt:    observed.Format(time.RFC3339),
		Scope:         reportScope{OS: "linux", Protocol: "ssh"},
		Categories:    map[string]coverage{},
		External:      []external{},
		SSHD:          sshdPolicy{MatchBlocks: []matchSettings{}, Daemon: daemon{Correspondence: "unresolved"}},
		SystemTrust:   []systemTrustFile{},
		Accounts:      []account{},
	}
	for _, name := range categoryNames {
		r.Categories[name] = coverage{Status: coverageUnknown, Reasons: []string{reasonParseError}}
	}
	body, err := seal(r)
	if err != nil {
		return nil, nil, ""
	}
	return r, body, ""
}

// checkBody is the canonical check request for a sealed report.
func checkBody(r *exposureReport) []byte {
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
		if errors.Is(err, scheduler.ErrExposureRequest) {
			log.Debug().Msg("Exposure request could not be built; skipping until the next read.")
			return status, false
		}
		if status == http.StatusTooManyRequests {
			log.Debug().Msg("Exposure delivery throttled; skipping until the next read.")
			return status, false
		}
		if status >= 300 && status < 400 || len(resp) > scheduler.MaxExposureResponseBytes || errors.Is(err, scheduler.ErrExposureResponseTooLarge) {
			log.Debug().Msg("Exposure response rejected; skipping until the next read.")
			return status, false
		}
		if status >= 400 && status < 500 && status != http.StatusRequestTimeout {
			return status, true
		}
		if err == nil && !retryable(status) {
			if out != nil && status == http.StatusOK {
				if json.NewDecoder(bytes.NewReader(resp)).Decode(out) != nil {
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
		if !s.sleep(ctx, backoff*8/10+rand.N(backoff*4/10+1)) {
			return 0, false
		}
		backoff = min(backoff*3, maxBackoff)
	}
}
