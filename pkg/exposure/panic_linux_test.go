//go:build linux

package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func acceptingPoster() *fakePoster {
	return &fakePoster{answers: map[string][]fakeResponse{
		checkURL:  {{status: 200, body: `{"required":true}`}},
		reportURL: {{status: 200}},
	}}
}

func installReadHook(t *testing.T, hook func(string)) {
	t.Helper()
	testHookReadStage = hook
	t.Cleanup(func() { testHookReadStage = nil })
}

func assertPanicLog(t *testing.T, logs string, stage, message string) {
	t.Helper()
	assert.NotContains(t, logs, "LEAKCANARY")
	require.Equal(t, 1, strings.Count(logs, "\n"), logs)
	assert.Contains(t, logs, message)
	assert.Contains(t, logs, `"category":"`+stage+`"`)
	assert.Regexp(t, `"source":"pkg/exposure/[a-z_]+\.go:[0-9]+"`, logs)
}

func decodeReport(t *testing.T, call postCall) *exposureReport {
	t.Helper()
	var r exposureReport
	require.NoError(t, json.Unmarshal(call.body, &r))
	sealed, err := seal(&r)
	require.NoError(t, err)
	assert.Equal(t, string(call.body), string(sealed), "body is canonical and hash covers the returned report")
	return &r
}

func TestReadParserPanicKeepsOtherCategoriesAndNextRead(t *testing.T) {
	logs := captureLogs(t)
	dir := filepath.Join(fixturesDir, "hosts", "ubuntu-default")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	c := newCollector(caseOptions(t, dir, spec, root, proc))
	var attempts atomic.Int32
	installReadHook(t, func(stage string) {
		if stage == "parser" && attempts.Add(1) == 1 {
			panic("LEAKCANARY parser bytes")
		}
	})
	p := acceptingPoster()
	s := testService(p, c.collect)
	for range 2 {
		s.readAndDeliver(context.Background())
	}
	reports := p.callsTo(reportURL)
	require.Len(t, reports, 2)
	first, next := decodeReport(t, reports[0]), decodeReport(t, reports[1])
	for _, name := range categoryNames {
		if name == catPasswords {
			assert.Equal(t, coverage{Status: coverageUnknown, Reasons: []string{reasonParseError}}, first.Categories[name])
		} else {
			assert.Equal(t, coverage{Status: coverageCovered, Reasons: []string{}}, first.Categories[name], name)
		}
		assert.Equal(t, coverage{Status: coverageCovered, Reasons: []string{}}, next.Categories[name], name)
	}
	assertPanicLog(t, logs.String(), catPasswords, "Exposure category parser panicked.")
}

func TestReadBoundaryFallbackAndNextRead(t *testing.T) {
	for _, stage := range []string{"collect", "assemble", "finalize", "serialize", "fallback"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				var failed atomic.Bool
				installReadHook(t, func(at string) {
					if stage == "fallback" {
						if at == "finalize" && failed.CompareAndSwap(false, true) || at == "fallback" {
							panic("LEAKCANARY fallback bytes")
						}
					} else if at == stage && failed.CompareAndSwap(false, true) {
						panic("LEAKCANARY host bytes")
					}
				})
				p := acceptingPoster()
				s := newService(p, func(context.Context) *exposureReport {
					readHook("collect")
					readHook("assemble")
					return sampleReport()
				}, nil)
				s.jitter = func() time.Duration { return 0 }
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go s.run(ctx)
				synctest.Wait()
				want := 1
				if stage == "fallback" {
					want = 0
					assert.Empty(t, p.callsTo(checkURL))
					assertPanicLog(t, logs.String(), stage, "Exposure fallback builder panicked; skipping until the next read.")
				} else {
					reports := p.callsTo(reportURL)
					require.Len(t, reports, 1)
					r := decodeReport(t, reports[0])
					require.Len(t, r.Categories, 8)
					for _, name := range categoryNames {
						assert.Equal(t, coverage{Status: coverageUnknown, Reasons: []string{reasonParseError}}, r.Categories[name], name)
					}
					assert.Equal(t, schemaVersion, r.SchemaVersion)
					assert.Equal(t, reportScope{OS: "linux", Protocol: "ssh"}, r.Scope)
					assert.Equal(t, time.Now().UTC().Format(time.RFC3339), r.ObservedAt)
					assert.Empty(t, r.External)
					assert.Empty(t, r.Accounts)
					assert.Empty(t, r.SystemTrust)
					assert.Nil(t, r.UserCA)
					assert.Equal(t, sshdPolicy{MatchBlocks: []matchSettings{}, Daemon: daemon{Correspondence: "unresolved"}}, r.SSHD)
					// assemble is injected before the fixture's assembly stand-in.
					logStage := stage
					if stage == "assemble" {
						logStage = "collect"
					}
					assertPanicLog(t, logs.String(), logStage, "Exposure read panicked; recovered at read boundary.")
				}
				assert.Len(t, p.callsTo(reportURL), want)
				time.Sleep(readInterval)
				synctest.Wait()
				reports := p.callsTo(reportURL)
				require.Len(t, reports, want+1)
				assert.Equal(t, coverageCovered, decodeReport(t, reports[len(reports)-1]).Categories[catAccounts].Status)
			})
		})
	}
}

type panicPoster struct {
	calls atomic.Int32
	post  *fakePoster
}

func (p *panicPoster) PostExposure(ctx context.Context, url string, body any, timeout time.Duration) ([]byte, int, http.Header, error) {
	if p.calls.Add(1) == 1 {
		panic("LEAKCANARY response bytes")
	}
	return p.post.PostExposure(ctx, url, body, timeout)
}

func TestServicePanicRestartsAfterPauseAndKeepsDueTime(t *testing.T) {
	for _, at := range []string{"delivery", "scheduling"} {
		t.Run(at, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				p := acceptingPoster()
				s := newService(p, func(context.Context) *exposureReport { return sampleReport() }, make(chan struct{}, 1))
				var jitters int
				s.jitter = func() time.Duration {
					jitters++
					if at == "scheduling" && jitters == 2 {
						panic("LEAKCANARY scheduling")
					}
					return 10 * time.Minute
				}
				var pp *panicPoster
				if at == "delivery" {
					pp = &panicPoster{post: p}
					s.post = pp
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go s.run(ctx)
				synctest.Wait()
				// The trigger occurs five minutes before the original due time.
				time.Sleep(5 * time.Minute)
				s.trigger <- struct{}{}
				synctest.Wait()
				before := len(p.callsTo(checkURL))
				time.Sleep(loopRestartPause - time.Nanosecond)
				synctest.Wait()
				assert.Len(t, p.callsTo(checkURL), before)
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				assert.Len(t, p.callsTo(checkURL), before)
				time.Sleep(4 * time.Minute)
				synctest.Wait()
				if at == "scheduling" {
					assert.Len(t, p.callsTo(checkURL), before)
					time.Sleep(loopRestartPause)
					synctest.Wait()
				}
				assert.Len(t, p.callsTo(checkURL), before+1)
				assertPanicLog(t, logs.String(), "service", "Exposure service loop panicked; restarting after 60 seconds.")
			})
		})
	}
}

// The dispatcher integration helpers are private to package executor (which
// imports exposure through runner). Use a separate responding feature here.
// A subprocess proves an unhandled worker panic would fail the whole process.
func TestStartParserPanicProcessSurvives(t *testing.T) {
	if os.Getenv("EXPOSURE_PANIC_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		exe, err := os.Executable()
		require.NoError(t, err)
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestStartParserPanicProcessSurvives$")
		cmd.Env = append(os.Environ(), "EXPOSURE_PANIC_CHILD=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		assert.Contains(t, string(output), "PASS")
		assert.NotContains(t, string(output), "LEAKCANARY")
		return
	}
	logs := captureLogs(t)
	dir := filepath.Join(fixturesDir, "hosts", "ubuntu-default")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	opts := caseOptions(t, dir, spec, root, proc)
	testHookStartOptions = &opts
	t.Cleanup(func() { testHookStartOptions = nil })
	var panics atomic.Int32
	installReadHook(t, func(stage string) {
		if stage == "parser" {
			panics.Add(1)
			panic("LEAKCANARY process parser")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan chan string)
	go func() {
		for {
			select {
			case reply := <-requests:
				reply <- "pong"
			case <-ctx.Done():
				return
			}
		}
	}()
	p := &notifyingPoster{post: acceptingPoster(), reported: make(chan struct{}, 1)}
	Start(ctx, p)
	for range 3 {
		Trigger()
		select {
		case <-p.reported:
		case <-time.After(20 * time.Second):
			t.Fatal("exposure read did not finish")
		}
		reply := make(chan string, 1)
		requests <- reply
		select {
		case got := <-reply:
			assert.Equal(t, "pong", got)
		case <-time.After(time.Second):
			t.Fatal("other feature stopped answering")
		}
	}
	assert.GreaterOrEqual(t, panics.Load(), int32(3))
	assert.NotContains(t, logs.String(), "LEAKCANARY")
}

type notifyingPoster struct {
	post     *fakePoster
	reported chan struct{}
}

func (p *notifyingPoster) PostExposure(ctx context.Context, url string, body any, timeout time.Duration) ([]byte, int, http.Header, error) {
	b, status, header, err := p.post.PostExposure(ctx, url, body, timeout)
	if url == reportURL {
		p.reported <- struct{}{}
	}
	return b, status, header, err
}

func TestServiceDeliveryPanicKeepsAdvancedDueTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		p := &panicPoster{post: acceptingPoster()}
		s := newService(p, func(context.Context) *exposureReport { return sampleReport() }, nil)
		s.jitter = func() time.Duration { return 0 }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.run(ctx)
		synctest.Wait()
		assert.Equal(t, int32(1), p.calls.Load())
		time.Sleep(loopRestartPause - time.Nanosecond)
		synctest.Wait()
		assert.Equal(t, int32(1), p.calls.Load())
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		assert.Empty(t, p.post.callsTo(reportURL))
		time.Sleep(readInterval - loopRestartPause)
		synctest.Wait()
		assert.Len(t, p.post.callsTo(reportURL), 1)
		assertPanicLog(t, logs.String(), "service", "Exposure service loop panicked; restarting after 60 seconds.")
	})
}

func TestEncoderPanicReachesReadBoundary(t *testing.T) {
	logs := captureLogs(t)
	var failed atomic.Bool
	testHookEncodePanic = func() bool { return failed.CompareAndSwap(false, true) }
	defer func() { testHookEncodePanic = nil }()
	p := acceptingPoster()
	s := testService(p, func(context.Context) *exposureReport { return sampleReport() })
	s.readAndDeliver(context.Background())
	reports := p.callsTo(reportURL)
	require.Len(t, reports, 1)
	r := decodeReport(t, reports[0])
	for _, cat := range categoryNames {
		assert.Equal(t, coverage{Status: coverageUnknown, Reasons: []string{reasonParseError}}, r.Categories[cat])
	}
	assertPanicLog(t, logs.String(), "serialize", "Exposure read panicked; recovered at read boundary.")
	assert.Regexp(t, `"source":"pkg/exposure/canonical.go:[0-9]+"`, logs.String())
}

func TestCategoryStarterPanicReturnsTimeout(t *testing.T) {
	logs := captureLogs(t)
	dir := filepath.Join(fixturesDir, "hosts", "ubuntu-default")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	installReadHook(t, func(stage string) {
		if stage == "starter:"+catPasswords {
			panic("LEAKCANARY starter")
		}
	})
	r := newCollector(caseOptions(t, dir, spec, root, proc)).collect(context.Background())
	assert.Equal(t, coverage{Status: coverageUnknown, Reasons: []string{reasonTimeout}}, r.Categories[catPasswords])
	assert.Equal(t, coverageCovered, r.Categories[catKeys].Status)
	assertPanicLog(t, logs.String(), catPasswords, "Exposure category starter panicked.")
}

func TestAccountDispatcherPanicTimesOutCurrentAccount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		var failed atomic.Bool
		installReadHook(t, func(stage string) {
			if stage == "account_dispatch:"+catKeys && failed.CompareAndSwap(false, true) {
				panic("LEAKCANARY dispatcher")
			}
		})
		accounts := make([]passwdEntry, 12)
		for i := range accounts {
			accounts[i].name = fmt.Sprint(i)
		}
		c := newCollector(collectorOptions{budget: categoryBudget})
		results := map[string]string{}
		readAccountResults(context.Background(), c, catKeys, accounts, func(passwdEntry) int { return 1 }, func(a passwdEntry, v int, reason string) {
			results[a.name] = reason
			if reason == "" {
				assert.Equal(t, 1, v)
			}
		})
		require.Len(t, results, len(accounts))
		timedOut := 0
		for _, reason := range results {
			if reason != "" {
				assert.Equal(t, reasonTimeout, reason)
				timedOut++
			}
		}
		assert.Equal(t, 1, timedOut)
		assertPanicLog(t, logs.String(), catKeys, "Exposure account dispatcher panicked.")
	})
}

type alwaysPanicPoster struct{}

func (alwaysPanicPoster) PostExposure(context.Context, string, any, time.Duration) ([]byte, int, http.Header, error) {
	panic("LEAKCANARY persistent delivery")
}

func TestPersistentDeliveryPanicKeepsHourlyTimerAndTriggers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		var reads atomic.Int32
		s := newService(alwaysPanicPoster{}, func(context.Context) *exposureReport { reads.Add(1); return sampleReport() }, make(chan struct{}, 1))
		s.jitter = func() time.Duration { return 0 }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.run(ctx)
		synctest.Wait()
		assert.Equal(t, int32(1), reads.Load())
		for hour := range 3 {
			time.Sleep(5 * time.Minute)
			synctest.Wait()
			s.trigger <- struct{}{}
			synctest.Wait()
			assert.Equal(t, int32(2*hour+2), reads.Load())
			time.Sleep(55*time.Minute - time.Nanosecond)
			synctest.Wait()
			assert.Equal(t, int32(2*hour+2), reads.Load())
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			assert.Equal(t, int32(2*hour+3), reads.Load())
		}
		assert.NotContains(t, logs.String(), "LEAKCANARY")
		assert.Equal(t, int(reads.Load()), strings.Count(logs.String(), "Exposure service loop panicked; restarting after 60 seconds."))
	})
}
