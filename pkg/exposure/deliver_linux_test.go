//go:build linux

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"

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

func sampleReport() *exposureReport {
	r := newReport()
	for _, n := range categoryNames {
		r.Categories[n] = coverage{Status: coverageCovered, Reasons: []string{}}
	}
	r.Accounts = append(r.Accounts, account{Username: "deploy", UID: 1001, Groups: []string{"deploy"},
		Shadow: shadow{Status: shadowRead, PasswordState: passwordLocked},
		Home:   home{Status: statusRead, StrictModesOK: ptr(true)},
		Sudo:   accountSudo{Complete: true}})
	return r
}

func testService(p *fakePoster, collect func(context.Context) *exposureReport) *service {
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
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
	s.readAndDeliver(context.Background())

	checks := p.callsTo(checkURL)
	require.Len(t, checks, 1)
	assert.Empty(t, p.callsTo(reportURL))
	var check map[string]any
	require.NoError(t, json.Unmarshal(checks[0].body, &check))
	assert.Equal(t, map[string]any{"schema_version": float64(2), "observed_at": "2026-11-07T19:30:00Z", "hash": check["hash"]}, check)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, check["hash"])
	assert.NotContains(t, logs.String(), "deploy")
}

func TestDeliverSendsTheSealedBodyWhenRequired(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL:  {{status: 200, body: `{"required": true, "applied": false}`}},
		reportURL: {{status: 200, body: `{"accepted_hash": "x", "applied": true}`}},
	}}
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
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
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
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
					throttled := fakeResponse{status: http.StatusTooManyRequests, body: strings.Repeat("LEAKCANARY-429", scheduler.MaxExposureResponseBytes)}
					if bodyError {
						throttled.err = fmt.Errorf("LEAKCANARY-body-error")
					}
					p := &fakePoster{answers: map[string][]fakeResponse{
						checkURL:  {{status: 200, body: `{"required": true}`}},
						reportURL: {{status: 200}},
					}}
					p.answers[endpoint] = append([]fakeResponse{throttled}, p.answers[endpoint]...)
					s := newService(p, func(context.Context) *exposureReport { return sampleReport() }, make(chan struct{}, 1))
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
	s := testService(p, func(context.Context) *exposureReport { reads++; return sampleReport() })
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

func TestDeliverFallsBackToVersionOneFromEitherEndpoint(t *testing.T) {
	const refusal = `{"errors":[{"field":"/schema_version","code":"unsupported_schema_version"}]}`
	for _, tc := range []struct {
		name     string
		endpoint string
		paths    []string
	}{
		{"check refuses v2", checkURL, []string{checkURL, checkURL, reportURL}},
		{"report refuses v2", reportURL, []string{checkURL, reportURL, checkURL, reportURL}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			p := acceptingPoster()
			p.answers[tc.endpoint] = append([]fakeResponse{{status: http.StatusBadRequest, body: refusal}}, p.answers[tc.endpoint]...)
			var snapshot *exposureReport
			reads := 0
			s := testService(p, func(context.Context) *exposureReport {
				reads++
				snapshot = sampleReport()
				snapshot.Accounts[0].KeyFiles = []keyFile{{
					envelope:      envelope{Path: "/home/deploy/.ssh/authorized_keys", Status: statusRead, Complete: true},
					StrictModesOK: ptr(true),
				}}
				return snapshot
			})
			s.readAndDeliver(context.Background())
			require.Equal(t, 1, reads)
			require.Len(t, p.calls, len(tc.paths))
			for i, path := range tc.paths {
				assert.Equal(t, path, p.calls[i].url)
			}
			v2Body, err := seal(snapshot)
			require.NoError(t, err)
			v2Check := decodeTree(t, p.calls[0].body)
			assert.Equal(t, json.Number("2"), v2Check["schema_version"])
			assert.Equal(t, snapshot.Hash, v2Check["hash"])
			if tc.endpoint == reportURL {
				assert.Equal(t, v2Body, p.calls[1].body)
			}
			v1Check := decodeTree(t, p.calls[len(p.calls)-2].body)
			v1Body := p.calls[len(p.calls)-1].body
			assertVersionedReports(t, v1Body, v2Body)
			assert.Equal(t, map[string]any{
				"schema_version": json.Number("1"),
				"observed_at":    v2Check["observed_at"],
				"hash":           goldenHash(t, v1Body),
			}, v1Check)

			s.readAndDeliver(context.Background())
			require.Equal(t, 2, reads)
			require.Len(t, p.calls, len(tc.paths)+2)
			nextCheck, nextReport := p.calls[len(tc.paths)], p.calls[len(tc.paths)+1]
			assert.Equal(t, checkURL, nextCheck.url)
			assert.Equal(t, reportURL, nextReport.url)
			assert.Equal(t, json.Number("1"), decodeTree(t, nextCheck.body)["schema_version"])
			assert.Equal(t, json.Number("1"), decodeTree(t, nextReport.body)["schema_version"])
			assert.JSONEq(t, `{"level":"info","message":"Exposure schema version 2 was refused; using version 1 for this server until restart."}`, logs.String())
		})
	}
}

func TestVersionOneDeliveryUsesItsOwnByteLimit(t *testing.T) {
	const accountCount, keysPerAccount = 16, 400
	r := sampleReport()
	r.Accounts = nil
	r.ObservedAt = goldenObservedAt
	var comment, padding string
	keys := make([]key, keysPerAccount)
	for i := range keys {
		keys[i] = key{
			Fingerprint: fmt.Sprintf("SHA256:%043d", i), Type: "ssh-ed25519", Bits: 256,
			Authorizations: []authorization{{Count: 1, Role: "user_key", Comment: &comment}},
		}
	}
	for i := range accountCount {
		r.Accounts = append(r.Accounts, capAccount(fmt.Sprintf("user%02d", i), keys))
	}
	r.SSHD.Effective = map[string]*string{"allowusers": &padding}
	legacy := *r
	legacy.SchemaVersion = legacySchemaVersion
	base, err := seal(&legacy)
	require.NoError(t, err)
	require.Less(t, len(base), maxReportBytes)
	available := maxReportBytes - len(base)
	comment = strings.Repeat("x", available/(accountCount*keysPerAccount))
	padding = strings.Repeat("x", available%(accountCount*keysPerAccount))
	v1, err := seal(&legacy)
	require.NoError(t, err)
	require.Len(t, v1, maxReportBytes)
	v2, err := seal(r)
	require.NoError(t, err)
	require.Greater(t, len(v2), maxReportBytes)

	p := acceptingPoster()
	p.answers[reportURL] = append([]fakeResponse{{
		status: http.StatusBadRequest,
		body:   `{"errors":[{"field":"/schema_version","code":"unsupported_schema_version"}]}`,
	}}, p.answers[reportURL]...)
	reads := 0
	s := testService(p, func(context.Context) *exposureReport { reads++; return r })
	s.readAndDeliver(context.Background())

	assert.Equal(t, 1, reads)
	reports := p.callsTo(reportURL)
	require.Len(t, reports, 2)
	assert.LessOrEqual(t, len(reports[0].body), maxReportBytes)
	assert.Equal(t, maxReportBytes, len(reports[1].body))
	var delivered exposureReport
	require.NoError(t, json.Unmarshal(reports[1].body, &delivered))
	assert.Equal(t, legacySchemaVersion, delivered.SchemaVersion)
	assert.Equal(t, legacy.Hash, delivered.Hash)
	require.Len(t, delivered.Accounts, accountCount)
	for _, account := range delivered.Accounts {
		require.Len(t, account.KeyFiles, 1)
		assert.Len(t, account.KeyFiles[0].Keys, keysPerAccount, account.Username)
	}
}

func TestDeliverFallbackIsRememberedByServerURL(t *testing.T) {
	logs := captureLogs(t)
	const legacyURL = "https://example.test/legacy"
	const currentURL = "https://example.test/current"
	t.Cleanup(func() {
		schemaV1ByServer.Delete(legacyURL)
		schemaV1ByServer.Delete(currentURL)
	})
	var versions []json.Number
	client := &http.Client{Transport: exposureRoundTrip(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		version := decodeTree(t, body)["schema_version"].(json.Number)
		versions = append(versions, version)
		status, response := http.StatusOK, `{"required":false}`
		if strings.HasPrefix(req.URL.Path, "/legacy/") && version == "2" {
			status, response = http.StatusBadRequest, `{"errors":[{"code":"unsupported_schema_version"}]}`
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(response))}, nil
	})}
	for _, url := range []string{legacyURL, legacyURL, currentURL} {
		s := newService(&scheduler.Session{BaseURL: url, Client: client}, func(context.Context) *exposureReport {
			return sampleReport()
		}, nil)
		s.readAndDeliver(context.Background())
	}
	assert.Equal(t, []json.Number{"2", "1", "1", "2"}, versions)
	assert.Equal(t, 1, strings.Count(logs.String(), `"level":"info"`))
}

func TestDeliverUnknownFieldDoesNotFallBack(t *testing.T) {
	for _, endpoint := range []string{checkURL, reportURL} {
		t.Run(endpoint, func(t *testing.T) {
			logs := captureLogs(t)
			p := acceptingPoster()
			p.answers[endpoint] = []fakeResponse{{status: http.StatusBadRequest, body: `{"errors":[{"field":"/unsupported_schema_version","code":"unknown_field"}]}`}}
			s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
			s.readAndDeliver(context.Background())
			checks := p.callsTo(checkURL)
			require.Len(t, checks, 1)
			assert.Equal(t, json.Number("2"), decodeTree(t, checks[0].body)["schema_version"])
			if endpoint == checkURL {
				assert.Empty(t, p.callsTo(reportURL))
				assert.JSONEq(t, `{"level":"debug","status_code":400,"message":"Exposure check was not accepted."}`, logs.String())
			} else {
				assert.Len(t, p.callsTo(reportURL), 1)
				assert.JSONEq(t, `{"level":"warn","status_code":400,"message":"Exposure report was not accepted."}`, logs.String())
			}
		})
	}
}

func TestDeliverRejectedReportLogsNoBody(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{answers: map[string][]fakeResponse{
		checkURL:  {{status: 200, body: `{"required": true, "applied": false}`}},
		reportURL: {{status: 400, body: `{"errors": [{"field": "/accounts/0/username", "code": "LEAKCANARY"}]}`}},
	}}
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
	s.readAndDeliver(context.Background())

	assert.Len(t, p.callsTo(reportURL), 1, "a 400 is not retried")
	assert.Contains(t, logs.String(), "Exposure report was not accepted.")
	assert.NotContains(t, logs.String(), "LEAKCANARY")
	assert.NotContains(t, logs.String(), "deploy")
}

func TestDeliverGivesUpAfterBoundedAttempts(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 500}}}}
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
	s.readAndDeliver(context.Background())
	assert.Len(t, p.callsTo(checkURL), maxAttempts)
}

func TestObservedAtStrictlyIncreases(t *testing.T) {
	p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required": false}`}}}}
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
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
		s := newService(p, func(context.Context) *exposureReport {
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
		s := newService(p, func(context.Context) *exposureReport {
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
				assert.Equal(t, `id="test", key="test"`, r.Header.Get("authorization"))
				if code != 200 {
					w.Header().Set("Location", other.URL)
					w.WriteHeader(code)
					return
				}
				_, err := io.WriteString(w, strings.Repeat("LEAKCANARY", scheduler.MaxExposureResponseBytes))
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
				svc.sleep = func(context.Context, time.Duration) bool {
					assert.Fail(t, "rejected response must not retry")
					return false
				}
				result := svc.send(context.Background(), path, []byte(`{}`), time.Second, nil)
				assert.False(t, result.ok)
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
	assert.Equal(t, scheduler.MaxExposureResponseBytes+1, body.read)
	assert.True(t, body.closed)
}

func TestOversizedReportIsNotDelivered(t *testing.T) {
	logs := captureLogs(t)
	p := &fakePoster{}
	s := testService(p, func(context.Context) *exposureReport {
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

func TestRejectedResponsesAreNotRetried(t *testing.T) {
	for _, response := range []fakeResponse{
		{status: 301, err: fmt.Errorf("LEAKCANARY redirect")},
		{status: 307},
		{status: 200, body: strings.Repeat("x", scheduler.MaxExposureResponseBytes+1)},
		{status: 200, err: scheduler.ErrExposureResponseTooLarge},
	} {
		for _, url := range []string{checkURL, reportURL} {
			logs := captureLogs(t)
			p := &fakePoster{answers: map[string][]fakeResponse{url: {response}}}
			s := testService(p, nil)
			result := s.send(context.Background(), url, []byte(`{}`), time.Second, nil)
			assert.False(t, result.ok)
			assert.Len(t, p.callsTo(url), 1)
			assert.Equal(t, 1, strings.Count(logs.String(), "Exposure response rejected; skipping until the next read."))
			assert.NotContains(t, logs.String(), "LEAKCANARY")
		}
	}
}

func TestTriggerReadPreservesDueTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required":false}`}}}}
		s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
		s.now = time.Now
		due := time.Now().Add(time.Hour)
		s.due = due
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { s.runLoop(ctx); close(done) }()
		s.trigger <- struct{}{}
		synctest.Wait()
		assert.Len(t, p.callsTo(checkURL), 1)
		assert.Equal(t, due, s.due)
		cancel()
		<-done
	})
}

func TestPrivsepRecollection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var reads, stats atomic.Int32
		var missing, present atomic.Bool
		missing.Store(true)
		post := &fakePoster{answers: map[string][]fakeResponse{checkURL: {{status: 200, body: `{"required":false}`}}}}
		s := testService(post, func(context.Context) *exposureReport {
			reads.Add(1)
			r := sampleReport()
			if missing.Load() {
				r.Categories[catSSHD] = coverage{Status: coveragePartial, Reasons: []string{reasonSSHDPrivsepMissing}}
			}
			return r
		})
		s.now = time.Now
		s.privsepPresent = func() bool { stats.Add(1); return present.Load() }
		done := make(chan struct{})
		go func() { defer close(done); s.run(ctx) }()
		advance := func(d time.Duration) { time.Sleep(d); synctest.Wait() }
		synctest.Wait()
		assert.Equal(t, 1, int(reads.Load()))
		advance(time.Minute)
		assert.Equal(t, 1, int(stats.Load()))
		assert.Equal(t, 1, int(reads.Load()))
		present.Store(true)
		missing.Store(false)
		advance(time.Minute)
		assert.Equal(t, 2, int(reads.Load()))
		advance(2 * time.Minute)
		assert.Equal(t, 2, int(stats.Load()))
		assert.Equal(t, 2, int(reads.Load()))

		missing.Store(true)
		present.Store(false)
		requestRead(s.trigger)
		synctest.Wait()
		advance(time.Minute)
		assert.Equal(t, 3, int(stats.Load()))
		missing.Store(false)
		requestRead(s.trigger)
		synctest.Wait()
		advance(time.Minute)
		assert.Equal(t, 3, int(stats.Load()))
		assert.Equal(t, 4, int(reads.Load()))

		missing.Store(true)
		requestRead(s.trigger)
		synctest.Wait()
		cancel()
		<-done
		advance(2 * time.Minute)
		assert.Equal(t, 3, int(stats.Load()))
		assert.Equal(t, 5, int(reads.Load()))
	})
}
