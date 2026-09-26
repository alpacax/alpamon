package updater

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lockedPoster is a thread-safe fakePoster for reports sent from goroutines.
type lockedPoster struct {
	mu      sync.Mutex
	status  int
	reports []Report
}

func (p *lockedPoster) Post(_ string, body any, _ time.Duration) ([]byte, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reports = append(p.reports, body.(Report))
	status := p.status
	if status == 0 {
		status = http.StatusCreated
	}
	return nil, status, nil
}

func (p *lockedPoster) all() []Report {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Report(nil), p.reports...)
}

type resumeFixture struct {
	sm        *fakeServiceManager
	poster    *lockedPoster
	runner    *fakeRunner
	authed    chan struct{}
	statusErr atomic.Pointer[error]
	restarted atomic.Bool
	marker    *PendingUpgrade
	deps      ResumeDeps
}

// newResumeFixture writes a binary-method marker whose deadline is grace
// from now, with the new binary live and the old one kept as the rollback.
func newResumeFixture(t *testing.T, grace time.Duration) *resumeFixture {
	t.Helper()
	useTempMarkerDir(t)
	dir := t.TempDir()
	f := &resumeFixture{
		sm:     &fakeServiceManager{},
		poster: &lockedPoster{},
		runner: &fakeRunner{},
		authed: make(chan struct{}),
	}
	f.marker = binaryMarker(t, dir)
	f.marker.GuardUnit = "alpamon-upgrade-guard-1"
	f.marker.StartedAt = time.Now()
	f.marker.Deadline = time.Now().Add(grace)
	require.NoError(t, os.WriteFile(f.marker.BinaryPath, []byte("new"), 0755))
	require.NoError(t, os.WriteFile(f.marker.RollbackPath, []byte("old"), 0755))
	require.NoError(t, WritePending(f.marker))

	f.deps = ResumeDeps{
		Running:       "2.5.0",
		Authenticated: f.authed,
		PostStatus: func() error {
			if e := f.statusErr.Load(); e != nil {
				return *e
			}
			return nil
		},
		Poster:         f.poster,
		ServiceManager: f.sm,
		RequestRestart: func() { f.restarted.Store(true) },
		runCommand:     f.runner.run,
	}
	return f
}

func fileContent(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func assertGone(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist, path)
}

func TestResumePending_NoMarker(t *testing.T) {
	useTempMarkerDir(t)
	found, done := ResumePending(context.Background(), ResumeDeps{})
	assert.False(t, found)
	<-done
}

func TestResumePending_HealthyUpgradeIsConfirmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, 5*time.Minute)
		found, done := ResumePending(t.Context(), f.deps)
		require.True(t, found)

		time.Sleep(time.Minute) // reconnecting takes a while
		close(f.authed)
		<-done

		marker, err := LoadPending()
		require.NoError(t, err)
		assert.Nil(t, marker)
		assertGone(t, f.marker.RollbackPath)
		assert.Equal(t, "new", fileContent(t, f.marker.BinaryPath))

		restarts, _, disarmed := f.sm.snapshot()
		assert.Empty(t, restarts)
		assert.Equal(t, []string{"alpamon-upgrade-guard-1"}, disarmed)
		assert.Equal(t, []Report{{AttemptID: "att", FromVersion: "2.4.0", ToVersion: "2.5.0", Outcome: OutcomeSucceeded}}, f.poster.all())
	})
}

func TestResumePending_StatusIsRetriedWithinTheWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, 5*time.Minute)
		failing := errors.New("503")
		f.statusErr.Store(&failing)
		close(f.authed)

		_, done := ResumePending(t.Context(), f.deps)
		time.Sleep(time.Minute)
		f.statusErr.Store(nil)
		<-done

		assert.Equal(t, OutcomeSucceeded, f.poster.all()[0].Outcome)
		assert.Equal(t, "new", fileContent(t, f.marker.BinaryPath))
	})
}

func TestResumePending_NoReconnectRollsBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, 5*time.Minute)
		_, done := ResumePending(t.Context(), f.deps)
		<-done

		assert.Equal(t, "old", fileContent(t, f.marker.BinaryPath), "the previous binary is back")
		assertGone(t, f.marker.RollbackPath)

		marker, err := LoadPending()
		require.NoError(t, err)
		require.NotNil(t, marker, "the marker stays for the restored process to report")
		assert.Equal(t, ClassHealthCheckFailed, marker.RollbackClass)
		assert.Contains(t, marker.RollbackDetail, "did not reconnect")

		restarts, _, disarmed := f.sm.snapshot()
		assert.Equal(t, []time.Duration{RestartDelay}, restarts, "restarted through the service manager")
		assert.Empty(t, disarmed, "the guard stays armed until the restored process clears it")
		assert.False(t, f.restarted.Load())
		assert.Empty(t, f.poster.all(), "the restored process reports, not this one")
	})
}

func TestResumePending_StatusNeverAcceptedRollsBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, 2*time.Minute)
		failing := errors.New("status report returned 401")
		f.statusErr.Store(&failing)
		close(f.authed)

		_, done := ResumePending(t.Context(), f.deps)
		<-done

		marker, err := LoadPending()
		require.NoError(t, err)
		require.NotNil(t, marker)
		assert.Contains(t, marker.RollbackDetail, "could not report status")
		assert.Contains(t, marker.RollbackDetail, "401")
		assert.Equal(t, "old", fileContent(t, f.marker.BinaryPath))
	})
}

func TestResumePending_LateStartStillGetsAWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, -time.Hour) // deadline long past
		_, done := ResumePending(t.Context(), f.deps)
		time.Sleep(minConfirmWindow / 2)
		close(f.authed)
		<-done
		assert.Equal(t, OutcomeSucceeded, f.poster.all()[0].Outcome)
	})
}

func TestResumePending_FallsBackToInProcessRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		f.sm.restartErr = ErrNoServiceManager
		_, done := ResumePending(t.Context(), f.deps)
		<-done
		assert.True(t, f.restarted.Load())
	})
}

func TestResumePending_PackageRollback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		f.marker.Method = MethodPackage
		f.marker.BinaryPath, f.marker.RollbackPath = "", ""
		usePackageManager(t, utils.PkgApt)
		f.marker.PackageManager = utils.PkgApt
		f.marker.PreviousPackageVersion = "2.4.0"
		require.NoError(t, WritePending(f.marker))

		_, done := ResumePending(t.Context(), f.deps)
		<-done

		assert.Equal(t, [][]string{{"apt-get", "install", "-y", "--allow-downgrades", "alpamon=2.4.0"}}, f.runner.snapshot())
		restarts, _, disarmed := f.sm.snapshot()
		assert.Len(t, restarts, 1)
		assert.Equal(t, []string{"alpamon-upgrade-guard-1"}, disarmed, "the guard stands down while the reinstall runs")
	})
}

func TestResumePending_FailedPackageRollbackRearmsTheGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		f.marker.Method = MethodPackage
		f.marker.BinaryPath, f.marker.RollbackPath = "", ""
		usePackageManager(t, utils.PkgApt)
		f.marker.PackageManager = utils.PkgApt
		f.marker.PreviousPackageVersion = "2.4.0"
		require.NoError(t, WritePending(f.marker))
		f.runner.err = errors.New("E: Version '2.4.0' for 'alpamon' was not found")

		_, done := ResumePending(t.Context(), f.deps)
		<-done

		restarts, guards, disarmed := f.sm.snapshot()
		assert.Empty(t, restarts)
		assert.Equal(t, []string{"alpamon-upgrade-guard-1"}, disarmed)
		require.Len(t, guards, 1, "a fresh guard retries the reinstall")
		assert.Equal(t, guardMargin, guards[0].delay)
		marker, err := LoadPending()
		require.NoError(t, err)
		require.NotNil(t, marker)
		assert.Equal(t, guards[0].unit, marker.GuardUnit)
	})
}

func TestResumePending_FailedRollbackLeavesItToTheGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		require.NoError(t, os.Remove(f.marker.RollbackPath))

		_, done := ResumePending(t.Context(), f.deps)
		<-done

		marker, err := LoadPending()
		require.NoError(t, err)
		require.NotNil(t, marker)
		assert.Empty(t, marker.RollbackClass, "the marker is left exactly as it was")
		restarts, _, disarmed := f.sm.snapshot()
		assert.Empty(t, restarts)
		assert.Empty(t, disarmed)
	})
}

func TestResumePending_ShutdownLeavesMarker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, 5*time.Minute)
		ctx, cancel := context.WithCancel(t.Context())
		_, done := ResumePending(ctx, f.deps)
		time.Sleep(time.Minute)
		cancel()
		<-done

		marker, err := LoadPending()
		require.NoError(t, err)
		assert.NotNil(t, marker, "the next start repeats the health check")
		assert.Equal(t, "new", fileContent(t, f.marker.BinaryPath))
	})
}

func TestResumePending_RestoredProcessReportsRollback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		class      ErrorClass
		detail     string
		wantDetail string
	}{
		{"after its own health check", ClassHealthCheckFailed, "did not reconnect", "did not reconnect"},
		{"after the guard", "", "", "never started"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newResumeFixture(t, time.Minute)
				f.marker.RollbackClass, f.marker.RollbackDetail = tc.class, tc.detail
				require.NoError(t, WritePending(f.marker))
				f.deps.Running = "v2.4.0"

				_, done := ResumePending(t.Context(), f.deps)
				<-done

				marker, err := LoadPending()
				require.NoError(t, err)
				assert.Nil(t, marker)
				assertGone(t, f.marker.RollbackPath)
				_, _, disarmed := f.sm.snapshot()
				assert.Equal(t, []string{"alpamon-upgrade-guard-1"}, disarmed)

				reports := f.poster.all()
				require.Len(t, reports, 1)
				assert.Equal(t, OutcomeRolledBack, reports[0].Outcome)
				assert.Equal(t, ClassHealthCheckFailed, reports[0].ErrorClass)
				assert.Contains(t, reports[0].Detail, tc.wantDetail)
			})
		})
	}
}

func TestResumePending_UnexpectedVersion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		f.deps.Running = "2.9.9"
		_, done := ResumePending(t.Context(), f.deps)
		<-done

		reports := f.poster.all()
		require.Len(t, reports, 1)
		assert.Equal(t, OutcomeFailed, reports[0].Outcome)
		assert.Equal(t, ClassUnknown, reports[0].ErrorClass)
		marker, _ := LoadPending()
		assert.Nil(t, marker)
	})
}

func TestResumePending_ReportIsRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		f.poster.status = http.StatusBadGateway
		close(f.authed)
		_, done := ResumePending(t.Context(), f.deps)
		<-done
		assert.Len(t, f.poster.all(), reportAttempts)
	})
}

func TestResumePending_UnreadableMarkerIsRemoved(t *testing.T) {
	dir := useTempMarkerDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "upgrade.pending"), []byte("{"), 0600))
	found, _ := ResumePending(context.Background(), ResumeDeps{})
	assert.False(t, found)
	assertGone(t, filepath.Join(dir, "upgrade.pending"))
}

func TestResumePending_PackageRollbackAfterAPinnedDowngrade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		usePackageManager(t, utils.PkgYum)
		f.marker.Method = MethodPackage
		f.marker.BinaryPath, f.marker.RollbackPath = "", ""
		f.marker.PackageManager = utils.PkgYum
		f.marker.FromVersion, f.marker.ToVersion = "2.6.0", "2.5.0"
		f.marker.PreviousPackageVersion = "2.6.0"
		require.NoError(t, WritePending(f.marker))
		f.deps.Running = "2.5.0"

		_, done := ResumePending(t.Context(), f.deps)
		<-done
		assert.Equal(t, [][]string{{"yum", "install", "-y", "alpamon-2.6.0"}}, f.runner.snapshot(),
			"going back up after a downgrade is an install, not a downgrade")
	})
}

func TestResumePending_GuardAlreadyRolledBackThePackage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, time.Minute)
		usePackageManager(t, utils.PkgApt)
		f.marker.Method = MethodPackage
		f.marker.BinaryPath, f.marker.RollbackPath = "", ""
		f.marker.PackageManager = utils.PkgApt
		f.marker.PreviousPackageVersion = "2.4.0"
		require.NoError(t, WritePending(f.marker))
		f.sm.fired = true

		_, done := ResumePending(t.Context(), f.deps)
		<-done
		assert.Empty(t, f.runner.snapshot(), "no second reinstall next to the guard's")
		restarts, _, _ := f.sm.snapshot()
		assert.Empty(t, restarts)
	})
}

func TestResumePending_GuardFiredBeforeConfirmation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newResumeFixture(t, 5*time.Minute)
		f.sm.fired = true
		close(f.authed)

		_, done := ResumePending(t.Context(), f.deps)
		<-done

		marker, err := LoadPending()
		require.NoError(t, err)
		require.NotNil(t, marker, "the marker is put back for the restored version to report")
		assert.Empty(t, f.poster.all(), "success is not reported")
	})
}
