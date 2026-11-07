//go:build linux

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func (f *fakePoster) PostExposure(_ context.Context, url string, body any, _ time.Duration) ([]byte, int, http.Header, error) {
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

func TestDeliver429SkipsUntilNextDueRead(t *testing.T) {
	for _, endpoint := range []string{checkURL, reportURL} {
		for _, bodyError := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/body error=%t", endpoint, bodyError), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					logs := captureLogs(t)
					throttled := fakeResponse{status: http.StatusTooManyRequests, body: strings.Repeat("LEAKCANARY-429", maxRespBytes)}
					if bodyError {
						throttled.err = fmt.Errorf("LEAKCANARY-body-error")
					}
					p := &fakePoster{answers: map[string][]fakeResponse{
						checkURL:  {{status: 200, body: `{"required": true}`}},
						reportURL: {{status: 200}},
					}}
					p.answers[endpoint] = append([]fakeResponse{throttled}, p.answers[endpoint]...)
					s := newService(p, func(context.Context) *Report { return sampleReport() }, make(chan struct{}, 1))
					s.jitter = func() time.Duration { return 0 }
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					go s.run(ctx)
					synctest.Wait()

					assert.Len(t, p.callsTo(checkURL), 1)
					if endpoint == checkURL {
						assert.Empty(t, p.callsTo(reportURL))
					} else {
						assert.Len(t, p.callsTo(reportURL), 1)
					}
					assert.Equal(t, "{\"level\":\"debug\",\"message\":\"Exposure delivery throttled; skipping until the next read.\"}\n", logs.String())
					time.Sleep(readInterval - time.Second)
					synctest.Wait()
					assert.Len(t, p.callsTo(checkURL), 1, "no attempts before the next due read")
					time.Sleep(time.Second)
					synctest.Wait()
					assert.Len(t, p.callsTo(checkURL), 2)
					wantReports := 1
					if endpoint == reportURL {
						wantReports = 2
					}
					assert.Len(t, p.callsTo(reportURL), wantReports)
					assert.Equal(t, 1, strings.Count(logs.String(), "\n"))
				})
			})
		}
	}
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

func TestExposureResponseLimitAndNoRedirect(t *testing.T) {
	var received atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(200) }))
	defer other.Close()
	for _, code := range []int{200, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, `id="test", key="test"`, r.Header.Get("Authorization"))
				if code != 200 {
					w.Header().Set("Location", other.URL)
					w.WriteHeader(code)
					return
				}
				_, err := io.WriteString(w, strings.Repeat("LEAKCANARY", maxRespBytes))
				if err != nil {
					return
				}
			}))
			defer origin.Close()
			session := &scheduler.Session{BaseURL: origin.URL, Authorization: `id="test", key="test"`, Client: origin.Client()}
			originalRedirect := session.Client.CheckRedirect
			for _, path := range []string{checkURL, reportURL} {
				body, status, _, err := session.PostExposure(context.Background(), path, []byte(`{"x":1}`), time.Second)
				assert.Error(t, err)
				assert.Empty(t, body)
				assert.Equal(t, code, status)
				svc := newService(session, nil, nil)
				svc.sleep = func(context.Context, time.Duration) bool { t.Error("rejected response must not retry"); return false }
				_, ok := svc.send(context.Background(), path, []byte(`{}`), time.Second, nil)
				assert.False(t, ok)
			}
			assert.Equal(t, int32(0), received.Load())
			assert.Equal(t, fmt.Sprintf("%p", originalRedirect), fmt.Sprintf("%p", session.Client.CheckRedirect))
		})
	}
}

type countingResponseBody struct {
	read   int
	closed bool
}

func (b *countingResponseBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += len(p)
	return len(p), nil
}
func (b *countingResponseBody) Close() error { b.closed = true; return nil }

type exposureRoundTrip func(*http.Request) (*http.Response, error)

func (f exposureRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExposureReadsAtMostResponseCapPlusOne(t *testing.T) {
	body := &countingResponseBody{}
	session := &scheduler.Session{BaseURL: "https://example.test", Client: &http.Client{Transport: exposureRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: http.Header{}}, nil
	})}}
	data, _, _, err := session.PostExposure(context.Background(), checkURL, []byte(`{}`), time.Second)
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, maxRespBytes+1, body.read)
	assert.True(t, body.closed)
}

func TestOversizedReportIsNotDelivered(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{}
	s := testService(p, func(context.Context) *Report {
		r := sampleReport()
		// No account-source cut can remove oversized configuration metadata.
		r.SSHD.Effective = map[string]*string{"allowusers": ptr(strings.Repeat("a", maxReportBytes))}
		return r
	})
	s.readAndDeliver(context.Background())
	assert.Empty(t, p.callsTo(checkURL))
	assert.Empty(t, p.callsTo(reportURL))
	assert.Equal(t, 1, strings.Count(logs.String(), "Exposure report exceeds the byte limit; skipping until the next read."))
}

func TestReportPanicDoesNotStopNextDueRead(t *testing.T) {
	for _, where := range []string{"collect", "finalize"} {
		t.Run(where, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required": false}`}}}}
				var reads atomic.Int32
				s := newService(p, func(context.Context) *Report {
					if reads.Add(1) == 1 {
						if where == "collect" {
							panic("LEAKCANARY")
						}
						r := sampleReport()
						// The byte cap calls markCut, which panics on this injected nil map.
						r.Categories = nil
						r.Accounts[0].Username = strings.Repeat("LEAKCANARY", maxAccountBytes)
						return r
					}
					return sampleReport()
				}, nil)
				s.jitter = func() time.Duration { return 0 }
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go s.run(ctx)
				synctest.Wait()
				require.Equal(t, int32(1), reads.Load())
				assert.Empty(t, p.callsTo(checkURL))
				assert.Empty(t, p.callsTo(reportURL))
				assert.Equal(t, 1, strings.Count(logs.String(), "Exposure report builder panicked; skipping until the next read."))
				assert.NotContains(t, logs.String(), "LEAKCANARY")
				if where == "finalize" {
					assert.Regexp(t, `"source":"pkg/exposure/cap.go:[0-9]+"`, logs.String())
				} else {
					assert.Regexp(t, `"source":"pkg/exposure/deliver_linux_test.go:[0-9]+"`, logs.String())
				}
				time.Sleep(readInterval)
				synctest.Wait()
				assert.Equal(t, int32(2), reads.Load())
				assert.Len(t, p.callsTo(checkURL), 1)
			})
		})
	}
}

func TestRejectedResponsesAreNotRetried(t *testing.T) {
	for _, response := range []fakeResponse{
		{status: 301, err: fmt.Errorf("LEAKCANARY redirect")},
		{status: 307},
		{status: 200, body: strings.Repeat("x", maxRespBytes+1)},
		{status: 200, err: scheduler.ErrExposureResponseTooLarge},
	} {
		for _, url := range []string{checkURL, reportURL} {
			logs := captureLogs(t)
			p := &fakePoster{answers: map[string][]fakeResponse{url: {response}}}
			s := testService(p, nil)
			_, ok := s.send(context.Background(), url, []byte(`{}`), time.Second, nil)
			assert.False(t, ok)
			assert.Len(t, p.callsTo(url), 1)
			assert.Equal(t, 1, strings.Count(logs.String(), "Exposure response rejected; skipping until the next read."))
			assert.NotContains(t, logs.String(), "LEAKCANARY")
		}
	}
}
