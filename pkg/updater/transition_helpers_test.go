package updater

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeServiceManager records what would have been scheduled.
type fakeServiceManager struct {
	mu         sync.Mutex
	restarts   []time.Duration
	guards     []fakeGuard
	disarmed   []string
	restartErr error
	guardErr   error
}

type fakeGuard struct {
	unit   string
	delay  time.Duration
	script string
}

func (f *fakeServiceManager) ScheduleRestart(d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.restartErr != nil {
		return f.restartErr
	}
	f.restarts = append(f.restarts, d)
	return nil
}

func (f *fakeServiceManager) ArmGuard(unit string, d time.Duration, script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.guardErr != nil {
		return f.guardErr
	}
	f.guards = append(f.guards, fakeGuard{unit, d, script})
	return nil
}

func (f *fakeServiceManager) DisarmGuard(unit string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disarmed = append(f.disarmed, unit)
}

func (f *fakeServiceManager) snapshot() (restarts []time.Duration, guards []fakeGuard, disarmed []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.restarts...), append([]fakeGuard(nil), f.guards...), append([]string(nil), f.disarmed...)
}

// useTempMarkerDir points the marker at a fresh directory for this test.
func useTempMarkerDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(OverrideMarkerDir(dir))
	return dir
}

// fakeRunner records commands instead of running them.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	err   error
	out   []byte
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

func (f *fakeRunner) snapshot() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}
