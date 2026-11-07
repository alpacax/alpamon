//go:build linux

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type postCall struct {
	url  string
	body []byte
}

type fakeResponse struct {
	status int
	body   string
	err    error
}

// fakePoster answers each URL from its own script; the last answer repeats.
type fakePoster struct {
	mu      sync.Mutex
	calls   []postCall
	answers map[string][]fakeResponse
}

func (f *fakePoster) PostWithContext(_ context.Context, url string, body any, _ time.Duration) ([]byte, int, http.Header, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := body.([]byte)
	if !ok {
		panic("exposure posts pre-encoded bytes only")
	}
	f.calls = append(f.calls, postCall{url: url, body: bytes.Clone(b)})
	list := f.answers[url]
	if len(list) == 0 {
		return nil, 0, nil, context.DeadlineExceeded
	}
	a := list[0]
	if len(list) > 1 {
		f.answers[url] = list[1:]
	}
	return []byte(a.body), a.status, http.Header{}, a.err
}

func (f *fakePoster) callsTo(url string) []postCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []postCall
	for _, c := range f.calls {
		if c.url == url {
			out = append(out, c)
		}
	}
	return out
}

func sampleReport() *Report {
	r := newReport()
	for _, n := range categoryNames {
		r.Categories[n] = Coverage{Status: coverageCovered, Reasons: []string{}}
	}
	r.Accounts = append(r.Accounts, Account{Username: "deploy", UID: 1001, Groups: []string{"deploy"},
		Shadow: Shadow{Status: shadowRead, PasswordState: passwordLocked},
		Home:   Home{Status: statusRead, StrictModesOK: ptr(true)},
		Sudo:   AccountSudo{Complete: true}})
	return r
}

func testService(p *fakePoster, collect func(context.Context) *Report) *service {
	s := newService(p, collect, make(chan struct{}, 1))
	s.now = func() time.Time { return time.Date(2026, 11, 7, 19, 30, 0, 0, time.UTC) }
	s.sleep = func(context.Context, time.Duration) bool { return true }
	s.jitter = func() time.Duration { return 0 }
	return s
}

func TestDeliverReportsOnlyWhenRequired(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL: {{status: 200, body: `{"required": false, "applied": true}`}},
	}}
	s := testService(p, func(context.Context) *Report { return sampleReport() })
	s.readAndDeliver(context.Background())

	checks := p.callsTo(checkURL)
	require.Len(t, checks, 1)
	assert.Empty(t, p.callsTo(reportURL))
	var check map[string]any
	require.NoError(t, json.Unmarshal(checks[0].body, &check))
	assert.Equal(t, map[string]any{"schema_version": float64(1), "observed_at": "2026-11-07T19:30:00Z", "hash": check["hash"]}, check)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, check["hash"])
	assert.NotContains(t, logs.String(), "deploy")
}

func TestDeliverSendsTheSealedBodyWhenRequired(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL:  {{status: 200, body: `{"required": true, "applied": false}`}},
		reportURL: {{status: 200, body: `{"accepted_hash": "x", "applied": true}`}},
	}}
	s := testService(p, func(context.Context) *Report { return sampleReport() })
	s.readAndDeliver(context.Background())

	reports := p.callsTo(reportURL)
	require.Len(t, reports, 1)
	want := sampleReport()
	want.ObservedAt = "2026-11-07T19:30:00Z"
	body, err := finalize(want)
	require.NoError(t, err)
	assert.Equal(t, string(body), string(reports[0].body))
	var check map[string]any
	require.NoError(t, json.Unmarshal(p.callsTo(checkURL)[0].body, &check))
	assert.Equal(t, want.Hash, check["hash"])
}

func TestDeliverCheck404SkipsWithOneFixedLine(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL: {{status: 404, body: `<html>LEAKCANARY-404-page</html>`}},
	}}
	s := testService(p, func(context.Context) *Report { return sampleReport() })
	s.readAndDeliver(context.Background())

	assert.Len(t, p.callsTo(checkURL), 1, "a 404 is not retried")
	assert.Empty(t, p.callsTo(reportURL))
	assert.Equal(t, 1, bytes.Count([]byte(logs.String()), []byte("Exposure check endpoint not available")))
	assert.NotContains(t, logs.String(), "LEAKCANARY")
}

func TestDeliverRetriesResendTheSameBody(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL:  {{status: 503, body: "LEAKCANARY-503"}, {err: context.DeadlineExceeded}, {status: 200, body: `{"required": true, "applied": false}`}},
		reportURL: {{status: 502, body: "LEAKCANARY-502"}, {status: 200, body: `{}`}},
	}}
	reads := 0
	s := testService(p, func(context.Context) *Report { reads++; return sampleReport() })
	s.readAndDeliver(context.Background())

	assert.Equal(t, 1, reads, "a retry never re-reads the host")
	checks, reports := p.callsTo(checkURL), p.callsTo(reportURL)
	require.Len(t, checks, 3)
	require.Len(t, reports, 2)
	for _, c := range checks[1:] {
		assert.Equal(t, checks[0].body, c.body)
	}
	assert.Equal(t, reports[0].body, reports[1].body)
	assert.NotContains(t, logs.String(), "LEAKCANARY")
}

func TestDeliverRejectedReportLogsNoBody(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL:  {{status: 200, body: `{"required": true, "applied": false}`}},
		reportURL: {{status: 400, body: `{"errors": [{"field": "/accounts/0/username", "code": "LEAKCANARY"}]}`}},
	}}
	s := testService(p, func(context.Context) *Report { return sampleReport() })
	s.readAndDeliver(context.Background())

	assert.Len(t, p.callsTo(reportURL), 1, "a 400 is not retried")
	assert.Contains(t, logs.String(), "Exposure report was not accepted.")
	assert.NotContains(t, logs.String(), "LEAKCANARY")
	assert.NotContains(t, logs.String(), "deploy")
}

func TestDeliverGivesUpAfterBoundedAttempts(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 500}}}}
	s := testService(p, func(context.Context) *Report { return sampleReport() })
	s.readAndDeliver(context.Background())
	assert.Len(t, p.callsTo(checkURL), maxAttempts)
}

func TestObservedAtStrictlyIncreases(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required": false}`}}}}
	s := testService(p, func(context.Context) *Report { return sampleReport() })
	s.readAndDeliver(context.Background())
	s.readAndDeliver(context.Background())
	checks := p.callsTo(checkURL)
	require.Len(t, checks, 2)
	var a, b map[string]any
	require.NoError(t, json.Unmarshal(checks[0].body, &a))
	require.NoError(t, json.Unmarshal(checks[1].body, &b))
	assert.Equal(t, "2026-11-07T19:30:00Z", a["observed_at"])
	assert.Equal(t, "2026-11-07T19:30:01Z", b["observed_at"])
}

// A trigger during a read schedules exactly one more read, however many
// arrive; the hourly due time keeps its own schedule.
func TestTriggersDuringAReadCoalesce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required": false}`}}}}
		release := make(chan struct{})
		started := make(chan struct{}, 10)
		var mu sync.Mutex
		reads := 0
		trig := make(chan struct{}, 1)
		s := newService(p, func(context.Context) *Report {
			mu.Lock()
			reads++
			n := reads
			mu.Unlock()
			started <- struct{}{}
			if n == 1 {
				<-release
			}
			return sampleReport()
		}, trig)
		s.jitter = func() time.Duration { return time.Hour * 1000 }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.run(ctx)

		trig <- struct{}{}
		<-started
		for range 5 {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
		close(release)
		<-started
		synctest.Wait()
		mu.Lock()
		assert.Equal(t, 2, reads)
		mu.Unlock()
		assert.Len(t, p.callsTo(checkURL), 2)
	})
}

func TestHourlyDueTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required": false}`}}}}
		var mu sync.Mutex
		reads := 0
		s := newService(p, func(context.Context) *Report {
			mu.Lock()
			reads++
			mu.Unlock()
			return sampleReport()
		}, make(chan struct{}, 1))
		s.jitter = func() time.Duration { return time.Minute }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.run(ctx)

		time.Sleep(time.Minute + time.Second)
		synctest.Wait()
		mu.Lock()
		assert.Equal(t, 1, reads, "first read after the start jitter")
		mu.Unlock()
		time.Sleep(readInterval + time.Minute)
		synctest.Wait()
		mu.Lock()
		assert.Equal(t, 2, reads, "next read one interval plus jitter later")
		mu.Unlock()
	})
}
