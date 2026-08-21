package migrate

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTempDataDir reroutes dataDirFn at a temporary directory so MarkerPath
// resolves under t.TempDir(). The original function is restored on cleanup.
// Uses the atomic-backed setter so concurrently-running watchdog
// goroutines from prior tests don't race with the swap.
func setupTempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := dataDirFnAtom.Load().(func() string)
	dataDirFnAtom.Store(func() string { return dir })
	t.Cleanup(func() { dataDirFnAtom.Store(orig) })
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0600), "write %s", path)
}

func TestWritePending_AndLoadPending_RoundTrip(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/alpamon.conf.bak.42",
		OldURL:         "https://a.example.com",
		NewURL:         "https://b.example.com",
		NewServerID:    "srv-xyz",
		NewServerKey:   "key-xyz",
		StartedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, WritePending(st))

	got, err := LoadPending()
	require.NoError(t, err)
	require.NotNil(t, got, "LoadPending returned nil after WritePending")
	assert.Equal(t, st.NewURL, got.NewURL)
	assert.Equal(t, st.NewServerID, got.NewServerID)

	// No .tmp leftover after a successful atomic rename.
	assert.NoFileExists(t, MarkerPath()+".tmp", "expected marker .tmp to be cleaned up")
}

func TestLoadPending_NoFile_ReturnsNilNil(t *testing.T) {
	setupTempDataDir(t)
	got, err := LoadPending()
	require.NoError(t, err, "LoadPending on missing file")
	assert.Nil(t, got, "LoadPending on missing file must return a nil state")
}

func TestConfirm_RemovesMarkerAndBackup(t *testing.T) {
	dataDir := setupTempDataDir(t)
	confDir := t.TempDir()
	backup := filepath.Join(confDir, "alpamon.conf.bak.123")
	writeFile(t, backup, "old config")

	st := &PendingState{
		BackupConfPath: backup,
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, WritePending(st))

	Confirm(st)

	assert.NoFileExists(t, MarkerPath(), "Confirm did not remove the marker")
	assert.NoFileExists(t, backup, "Confirm did not remove the backup")
	// Sanity: dataDir still exists.
	assert.DirExists(t, dataDir, "dataDir unexpectedly removed")
}

func TestConfirm_NilState_IsNoop(t *testing.T) {
	setupTempDataDir(t)
	assert.NotPanics(t, func() { Confirm(nil) })
}

func TestBackupConf_PreservesContentAndCleansUpOnNoError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "alpamon.conf")
	content := "[server]\nurl=https://a.example.com\n"
	writeFile(t, src, content)

	backup, err := BackupConf(src)
	require.NoError(t, err)
	assert.NotEqual(t, src, backup, "backup path must differ from the source")

	got, err := os.ReadFile(backup)
	require.NoError(t, err, "read backup")
	assert.Equal(t, content, string(got), "backup content mismatch")
}

func TestWriteConfAtomic_LeavesNoTmpFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "alpamon.conf")

	require.NoError(t, WriteConfAtomic(conf, []byte("new content"), 0600))

	got, err := os.ReadFile(conf)
	require.NoError(t, err, "read conf")
	assert.Equal(t, "new content", string(got))
	assert.NoFileExists(t, conf+".new", "expected .new to be cleaned up")
}

func TestRestoreBackup_RestoresContent(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "alpamon.conf.bak.1")
	dest := filepath.Join(dir, "alpamon.conf")
	writeFile(t, backup, "[server]\nold=true\n")
	writeFile(t, dest, "[server]\nnew=true\n")

	require.NoError(t, RestoreBackup(backup, dest))

	got, err := os.ReadFile(dest)
	require.NoError(t, err, "read dest")
	assert.Equal(t, "[server]\nold=true\n", string(got))
}

func TestRollback_RestoresConf(t *testing.T) {
	setupTempDataDir(t)
	confDir := t.TempDir()

	confPath := filepath.Join(confDir, "alpamon.conf")
	backupPath := filepath.Join(confDir, "alpamon.conf.bak.999")
	writeFile(t, backupPath, "[server]\nurl=https://a.example.com\n")
	writeFile(t, confPath, "[server]\nurl=https://b.example.com\n")

	st := &PendingState{
		BackupConfPath: backupPath,
		OldURL:         "https://a.example.com",
		NewURL:         "https://invalid.example.invalid", // unreachable on purpose
		NewServerID:    "srv-xyz",
		NewServerKey:   "key-xyz",
		StartedAt:      time.Now().Add(-10 * time.Minute),
		ExpiresAt:      time.Now().Add(-5 * time.Minute),
	}
	require.NoError(t, WritePending(st))

	// We deliberately do not assert on Rollback's return value: without
	// systemd, ScheduleSelfRestart fails and Rollback returns that error,
	// but the prior steps (restore + best-effort unregister) still ran.
	_ = Rollback(st, confPath, false, "")

	// Conf must be restored to backup content.
	got, err := os.ReadFile(confPath)
	require.NoError(t, err, "read conf")
	assert.Equal(t, "[server]\nurl=https://a.example.com\n", string(got), "conf not restored")
	// When ScheduleSelfRestart fails, the marker and backup must remain
	// so the next agent startup's watchdog can retry. This is the
	// post-review ordering: clean up durable state only after the restart
	// is queued.
	assert.FileExists(t, backupPath, "backup unexpectedly removed before restart was scheduled")
	assert.FileExists(t, MarkerPath(), "marker unexpectedly removed before restart was scheduled")
}

func TestRollback_TolerantOfMissingBackup(t *testing.T) {
	setupTempDataDir(t)
	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "alpamon.conf")
	writeFile(t, confPath, "restored already")

	st := &PendingState{
		BackupConfPath: filepath.Join(confDir, "alpamon.conf.bak.gone"),
		NewURL:         "https://invalid.example.invalid",
		NewServerID:    "srv-xyz",
		NewServerKey:   "key-xyz",
		ExpiresAt:      time.Now().Add(-time.Minute),
	}
	require.NoError(t, WritePending(st))

	// With backup gone, the restore step is skipped (warn logged) and
	// the rest of Rollback runs. ScheduleSelfRestart still fails on CI,
	// so we only assert on the no-overwrite invariant.
	_ = Rollback(st, confPath, false, "")

	got, err := os.ReadFile(confPath)
	require.NoError(t, err, "read conf")
	assert.Equal(t, "restored already", string(got), "Rollback overwrote conf when backup was missing")
}

func TestRollback_NilState_ReturnsError(t *testing.T) {
	assert.Error(t, Rollback(nil, "/tmp/x", false, ""), "expected error from Rollback(nil)")
}

func TestStartWatchdog_FiresOnTimeout(t *testing.T) {
	setupTempDataDir(t)

	// Timer margin sized for slow CI runners (containers with throttled
	// disks where WritePending alone can take 100ms+). Keep watchdog
	// timeouts in tests >= ~1s so a slow WritePending doesn't push
	// ExpiresAt into the past before StartWatchdog reads it.
	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(1 * time.Second),
	}
	require.NoError(t, WritePending(st))

	var fired atomic.Int32
	done := make(chan struct{})
	ctx := t.Context()

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
		close(done)
	})

	select {
	case <-done:
		assert.Equal(t, int32(1), fired.Load(), "expected a single fire")
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not fire within deadline")
	}
}

func TestStartWatchdog_DoesNotFireAfterConfirm(t *testing.T) {
	setupTempDataDir(t)

	// 3s window leaves plenty of room to call Confirm even if
	// WritePending takes several hundred ms on a slow CI runner.
	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(3 * time.Second),
	}
	require.NoError(t, WritePending(st))

	var fired atomic.Int32
	ctx := t.Context()

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
	})

	// Confirm well before the timer would fire.
	time.Sleep(200 * time.Millisecond)
	Confirm(st)

	// Wait past the original deadline plus jitter.
	time.Sleep(4 * time.Second)

	assert.Zero(t, fired.Load(), "watchdog fired despite Confirm")
}

func TestStartWatchdog_FiresImmediatelyIfAlreadyExpired(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(-time.Minute),
	}
	require.NoError(t, WritePending(st))

	done := make(chan struct{})
	ctx := t.Context()

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		close(done)
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not fire immediately for expired marker")
	}
}

func TestStartWatchdog_CancelDisarmsBeforeTimer(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(3 * time.Second),
	}
	require.NoError(t, WritePending(st))

	var fired atomic.Int32
	ctx := t.Context()

	cancelWatchdog := StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
	})

	// Disarm before the timer would fire — mirrors the on-connect-success
	// path that races against the watchdog.
	time.Sleep(200 * time.Millisecond)
	cancelWatchdog()

	time.Sleep(4 * time.Second)
	assert.Zero(t, fired.Load(), "watchdog fired despite cancel")
}

func TestStartWatchdog_StopsOnContextCancel(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(3 * time.Second),
	}
	require.NoError(t, WritePending(st))

	var fired atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
	})

	cancel()
	time.Sleep(4 * time.Second)

	assert.Zero(t, fired.Load(), "watchdog fired after ctx cancel")
}
