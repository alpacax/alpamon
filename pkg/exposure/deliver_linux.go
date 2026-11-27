//go:build linux

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
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

	privsepPollInterval = time.Minute

	checkTimeout  = 10 * time.Second
	reportTimeout = 60 * time.Second
	maxAttempts   = 5
	firstBackoff  = 5 * time.Second
	maxBackoff    = 5 * time.Minute
)

// schemaV1ByServer retains the negotiated version across services for each configured URL.
var schemaV1ByServer sync.Map // string to *atomic.Bool

// service serializes exposure reads and their delivery. A trigger that
// arrives during a read is held in a one-slot channel and causes exactly one
// more read after it.
type service struct {
	post           Poster
	collect        func(ctx context.Context) *exposureReport
	trigger        chan struct{}
	now            func() time.Time
	jitter         func() time.Duration
	sleep          func(ctx context.Context, d time.Duration) bool
	useV1          *atomic.Bool
	privsepPresent func() bool
	cancelPoll     context.CancelFunc
	pollDone       chan struct{}
	// lastObserved prevents replays within the same second. After a backward
	// clock step of more than 2 s, an earlier observed_at is sent on purpose;
	// the server may answer applied: false until the clock catches up.
	lastObserved     time.Time
	due              time.Time
	unavailableUntil time.Time
}

func newService(p Poster, collect func(ctx context.Context) *exposureReport, trigger chan struct{}) *service {
	useV1 := new(atomic.Bool)
	if session, ok := p.(*scheduler.Session); ok && session.BaseURL != "" {
		state, _ := schemaV1ByServer.LoadOrStore(session.BaseURL, useV1)
		useV1 = state.(*atomic.Bool)
	}
	return &service{
		post:    p,
		collect: collect,
		trigger: trigger,
		now:     time.Now,
		jitter:  func() time.Duration { return rand.N(maxReadJitter) },
		sleep:   sleepCtx,
		useV1:   useV1,
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
	defer s.stopPrivsepPoll()
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

func (s *service) stopPrivsepPoll() {
	if s.cancelPoll != nil {
		s.cancelPoll()
		<-s.pollDone
		s.cancelPoll = nil
	}
}

func (s *service) updatePrivsepPoll(ctx context.Context, snapshot *exposureReport) {
	if s.privsepPresent == nil || snapshot == nil || !slices.Contains(snapshot.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing) {
		s.stopPrivsepPoll()
		return
	}
	if s.cancelPoll != nil {
		select {
		case <-s.pollDone:
			s.cancelPoll()
		default:
			return
		}
	}
	ctx, s.cancelPoll = context.WithCancel(ctx)
	done := make(chan struct{})
	s.pollDone = done
	go func() {
		defer close(done)
		defer func() {
			if recover() != nil {
				logExposurePanic("sshd", "Exposure privilege separation directory check failed.")
			}
		}()
		ticker := time.NewTicker(privsepPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() == nil && s.privsepPresent() {
					if ctx.Err() == nil {
						requestRead(s.trigger)
					}
					return
				}
			}
		}
	}()
}

// readAndDeliver reads once and delivers the result: a check, then the
// report only when the server asks for it. Retries resend the same
// observed_at and body.
func (s *service) readAndDeliver(ctx context.Context) {
	if s.now().Before(s.unavailableUntil) {
		return
	}
	version := schemaVersion
	if s.useV1.Load() {
		version = legacySchemaVersion
	}
	r, body, snapshot := s.buildReport(ctx, version)
	s.updatePrivsepPoll(ctx, snapshot)
	if r == nil || !s.deliver(ctx, r, body) {
		return
	}
	if s.useV1.CompareAndSwap(false, true) {
		log.Info().Msg("Exposure schema version 2 was refused; using version 1 for this server until restart.")
	}
	if snapshot == nil {
		r, body, _ = fallbackReport(r.ObservedAt, legacySchemaVersion)
	} else {
		r, body = prepareReport(snapshot, legacySchemaVersion)
	}
	if r != nil {
		s.deliver(ctx, r, body)
	}
}

// deliver returns true when the same snapshot needs a new check using the v1 hash.
func (s *service) deliver(ctx context.Context, r *exposureReport, body []byte) bool {
	var res struct {
		Required *bool `json:"required"`
	}
	check := s.send(ctx, checkURL, checkBody(r), checkTimeout, &res)
	switch {
	case check.unsupportedVersion && r.SchemaVersion == schemaVersion:
		return true
	case check.status == http.StatusNotFound:
		s.unavailableUntil = s.now().Add(24 * time.Hour)
		log.Debug().Msg("Exposure check endpoint not available on this server; skipping for 24 hours.")
		return false
	case !check.ok:
		return false
	case check.status != http.StatusOK || res.Required == nil:
		log.Debug().Int("status_code", check.status).Msg("Exposure check was not accepted.")
		return false
	case !*res.Required:
		return false
	}
	report := s.send(ctx, reportURL, body, reportTimeout, nil)
	if report.unknownReasonField != "" {
		if legacy := legacySSHDReport(r, report.unknownReasonField); legacy != nil {
			report = s.sendAttempts(ctx, reportURL, legacy, reportTimeout, nil, 1)
		}
	}
	if report.unsupportedVersion && r.SchemaVersion == schemaVersion {
		return true
	}
	if report.ok && report.status != http.StatusOK {
		log.Warn().Int("status_code", report.status).Msg("Exposure report was not accepted.")
	}
	return false
}

// legacySSHDReport only downgrades the reason at the exact rejected JSON pointer.
func legacySSHDReport(report *exposureReport, field string) []byte {
	c := report.Categories[catSSHD]
	for i, reason := range c.Reasons {
		switch reason {
		case reasonSSHDPrivsepMissing, reasonSSHDBinaryRejected, reasonSSHDTimeout:
			if field != "/categories/sshd/reasons/"+strconv.Itoa(i) {
				continue
			}
			snapshot := report
			if report.unavailableSSHD != nil {
				snapshot = report.unavailableSSHD()
			}
			legacy := reportForVersion(snapshot, report.SchemaVersion)
			legacy.ObservedAt = report.ObservedAt
			c = legacy.Categories[catSSHD]
			reasons := reasonSet{}
			reasons.add(c.Reasons...)
			delete(reasons, reason)
			reasons.add(reasonSSHDUnavailable)
			c.Reasons = reasons.list()
			legacy.Categories[catSSHD] = c
			legacy.SSHD.Effective = nil
			body, err := finalize(legacy)
			if err == nil && len(body) <= maxReportBytes {
				return body
			}
		}
	}
	return nil
}

func (s *service) buildReport(ctx context.Context, version int) (report *exposureReport, encoded []byte, snapshot *exposureReport) {
	stage := "collect"
	var observed time.Time
	defer func() {
		if recover() != nil {
			// Capture the original frame while its panic is still on the
			// stack. The fallback has its own boundary and bypasses all
			// collection, assembly and cap code, including their hooks.
			stage, location := exposurePanicDetails(stage)
			var fallbackSource string
			report, encoded, fallbackSource = fallbackReport(observed.Format(time.RFC3339), version)
			snapshot = nil
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
				return nil, nil, nil
			}
		}
	}
	s.lastObserved = observed

	snapshot = s.collect(ctx)
	snapshot.ObservedAt = observed.Format(time.RFC3339)
	stage = "finalize"
	report, encoded = prepareReport(snapshot, version)
	return report, encoded, snapshot
}

func prepareReport(snapshot *exposureReport, version int) (*exposureReport, []byte) {
	r := reportForVersion(snapshot, version)
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

func fallbackReport(observed string, version int) (report *exposureReport, encoded []byte, panicSource string) {
	defer func() {
		if recover() != nil {
			report, encoded = nil, nil
			panicSource = exposurePanicSource()
		}
	}()
	readHook("fallback")
	// The contract requires an sshd object. Use its empty policy form.
	r := &exposureReport{
		SchemaVersion: version,
		ObservedAt:    observed,
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
	b = append(b, `,"schema_version":`...)
	b = strconv.AppendInt(b, int64(r.SchemaVersion), 10)
	return append(b, '}')
}

func retryable(status int) bool {
	return status == http.StatusRequestTimeout || status >= 500
}

type deliveryResponse struct {
	status             int
	ok                 bool
	unsupportedVersion bool
	unknownReasonField string
}

func (r *deliveryResponse) readRefusal(body []byte) {
	var response struct {
		Errors []struct {
			Code  string `json:"code"`
			Field string `json:"field"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &response) != nil {
		return
	}
	for _, failure := range response.Errors {
		if failure.Code == "unsupported_schema_version" {
			r.unsupportedVersion = true
		}
	}
	if len(response.Errors) == 1 && response.Errors[0].Code == "unknown_reason" {
		r.unknownReasonField = response.Errors[0].Field
	}
}

// send posts body, retrying transport errors and retryable statuses with
// backoff. ok is false when delivery is deferred. Neither the request nor
// the response body is logged.
func (s *service) send(ctx context.Context, url string, body []byte, timeout time.Duration, out any) deliveryResponse {
	return s.sendAttempts(ctx, url, body, timeout, out, maxAttempts)
}

func (s *service) sendAttempts(ctx context.Context, url string, body []byte, timeout time.Duration, out any, attempts int) deliveryResponse {
	backoff := firstBackoff
	for attempt := 1; ; attempt++ {
		resp, status, _, err := s.post.PostExposure(ctx, url, body, timeout)
		if errors.Is(err, scheduler.ErrExposureRequest) {
			log.Debug().Msg("Exposure request could not be built; skipping until the next read.")
			return deliveryResponse{status: status}
		}
		if status == http.StatusTooManyRequests {
			log.Debug().Msg("Exposure delivery throttled; skipping until the next read.")
			return deliveryResponse{status: status}
		}
		if status >= 300 && status < 400 || len(resp) > scheduler.MaxExposureResponseBytes || errors.Is(err, scheduler.ErrExposureResponseTooLarge) {
			log.Debug().Msg("Exposure response rejected; skipping until the next read.")
			return deliveryResponse{status: status}
		}
		if status >= 400 && status < 500 && status != http.StatusRequestTimeout {
			r := deliveryResponse{status: status, ok: true}
			if status == http.StatusBadRequest && err == nil {
				r.readRefusal(resp)
			}
			return r
		}
		if err == nil && !retryable(status) {
			if out != nil && status == http.StatusOK {
				if json.NewDecoder(bytes.NewReader(resp)).Decode(out) != nil {
					log.Debug().Msg("Exposure check response could not be parsed.")
					return deliveryResponse{status: status}
				}
			}
			return deliveryResponse{status: status, ok: true}
		}
		if attempt >= attempts || ctx.Err() != nil {
			log.Debug().Int("status_code", status).Int("attempts", attempt).Msg("Exposure delivery gave up until the next read.")
			return deliveryResponse{status: status}
		}
		if !s.sleep(ctx, backoff*8/10+rand.N(backoff*4/10+1)) {
			return deliveryResponse{}
		}
		backoff = min(backoff*3, maxBackoff)
	}
}
