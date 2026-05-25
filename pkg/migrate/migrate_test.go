package migrate

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
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

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
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
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	got, err := LoadPending()
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	if got == nil {
		t.Fatalf("LoadPending returned nil after WritePending")
	}
	if got.NewURL != st.NewURL || got.NewServerID != st.NewServerID {
		t.Fatalf("LoadPending round-trip mismatch: %+v", got)
	}

	// No .tmp leftover after a successful atomic rename.
	if _, err := os.Stat(MarkerPath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected marker .tmp to be cleaned up; stat err=%v", err)
	}
}

func TestLoadPending_NoFile_ReturnsNilNil(t *testing.T) {
	setupTempDataDir(t)
	got, err := LoadPending()
	if err != nil {
		t.Fatalf("LoadPending on missing file: %v", err)
	}
	if got != nil {
		t.Fatalf("LoadPending on missing file: got %+v, want nil", got)
	}
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
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	Confirm(st)

	if _, err := os.Stat(MarkerPath()); !os.IsNotExist(err) {
		t.Fatalf("Confirm did not remove marker at %s (err=%v)", MarkerPath(), err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("Confirm did not remove backup at %s (err=%v)", backup, err)
	}
	// Sanity: dataDir still exists.
	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("dataDir unexpectedly removed: %v", err)
	}
}

func TestConfirm_NilState_IsNoop(t *testing.T) {
	setupTempDataDir(t)
	Confirm(nil) // must not panic
}

func TestBackupConf_PreservesContentAndCleansUpOnNoError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "alpamon.conf")
	content := "[server]\nurl=https://a.example.com\n"
	writeFile(t, src, content)

	backup, err := BackupConf(src)
	if err != nil {
		t.Fatalf("BackupConf: %v", err)
	}
	if backup == src {
		t.Fatalf("backup path equals source")
	}
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(got) != content {
		t.Fatalf("backup content mismatch:\nwant %q\ngot  %q", content, string(got))
	}
}

func TestWriteConfAtomic_LeavesNoTmpFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "alpamon.conf")

	if err := WriteConfAtomic(conf, []byte("new content"), 0600); err != nil {
		t.Fatalf("WriteConfAtomic: %v", err)
	}
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read conf: %v", err)
	}
	if string(got) != "new content" {
		t.Fatalf("conf content mismatch: %q", string(got))
	}
	if _, err := os.Stat(conf + ".new"); !os.IsNotExist(err) {
		t.Fatalf("expected .new to be cleaned up; stat err=%v", err)
	}
}

func TestRestoreBackup_RestoresContent(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "alpamon.conf.bak.1")
	dest := filepath.Join(dir, "alpamon.conf")
	writeFile(t, backup, "[server]\nold=true\n")
	writeFile(t, dest, "[server]\nnew=true\n")

	if err := RestoreBackup(backup, dest); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "[server]\nold=true\n" {
		t.Fatalf("RestoreBackup content mismatch: %q", string(got))
	}
}

func TestRollback_RestoresConfAndCleansUpEverything(t *testing.T) {
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
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	err := Rollback(st, confPath, false, "")
	// systemd-run is almost certainly unavailable in CI; we expect the
	// ScheduleSelfRestart step to fail. Everything BEFORE that step should
	// still have executed so cleanup is verifiable.
	if err == nil {
		t.Log("Rollback returned nil — ScheduleSelfRestart succeeded (presumably systemd is available).")
	}

	// Conf must be restored to backup content.
	got, _ := os.ReadFile(confPath)
	if string(got) != "[server]\nurl=https://a.example.com\n" {
		t.Fatalf("conf not restored, got %q", string(got))
	}
	// Backup file must be removed.
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("backup not cleaned up: stat err=%v", err)
	}
	// Marker must be removed.
	if _, err := os.Stat(MarkerPath()); !os.IsNotExist(err) {
		t.Fatalf("marker not cleaned up: stat err=%v", err)
	}
	// No leftover .new / .tmp anywhere in confDir.
	entries, _ := os.ReadDir(confDir)
	for _, e := range entries {
		name := e.Name()
		if name == filepath.Base(confPath) {
			continue
		}
		t.Fatalf("unexpected leftover in confDir: %s", name)
	}
}

func TestRollback_IdempotentWhenBackupMissing(t *testing.T) {
	setupTempDataDir(t)
	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "alpamon.conf")
	writeFile(t, confPath, "restored already")

	st := &PendingState{
		BackupConfPath: filepath.Join(confDir, "alpamon.conf.bak.gone"),
		NewURL:         "https://invalid.example.invalid",
		NewServerID:    "srv-xyz",
		NewServerKey:   "key-xyz",
		ExpiresAt:      time.Now().Add(-1 * time.Minute),
	}
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	// Should not error on the restore step despite missing backup. The
	// final ScheduleSelfRestart step may still fail on CI without systemd;
	// that is acceptable for this test, which is about cleanup idempotency.
	_ = Rollback(st, confPath, false, "")

	if got, _ := os.ReadFile(confPath); string(got) != "restored already" {
		t.Fatalf("Rollback overwrote conf when backup was missing: %q", string(got))
	}
	if _, err := os.Stat(MarkerPath()); !os.IsNotExist(err) {
		t.Fatalf("marker not cleaned up despite missing backup")
	}
}

func TestRollback_NilState_ReturnsError(t *testing.T) {
	if err := Rollback(nil, "/tmp/x", false, ""); err == nil {
		t.Fatalf("expected error from Rollback(nil), got nil")
	}
}

func TestStartWatchdog_FiresOnTimeout(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(50 * time.Millisecond),
	}
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	var fired atomic.Int32
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
		close(done)
	})

	select {
	case <-done:
		if fired.Load() != 1 {
			t.Fatalf("expected single fire, got %d", fired.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("watchdog did not fire within deadline")
	}
}

func TestStartWatchdog_DoesNotFireAfterConfirm(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(80 * time.Millisecond),
	}
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
	})

	// Race-free Confirm before the timer would fire.
	time.Sleep(10 * time.Millisecond)
	Confirm(st)

	// Wait past the original deadline plus jitter.
	time.Sleep(200 * time.Millisecond)

	if fired.Load() != 0 {
		t.Fatalf("watchdog fired despite Confirm: count=%d", fired.Load())
	}
}

func TestStartWatchdog_FiresImmediatelyIfAlreadyExpired(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(-1 * time.Minute),
	}
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		close(done)
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("watchdog did not fire immediately for expired marker")
	}
}

func TestStartWatchdog_CancelDisarmsBeforeTimer(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(200 * time.Millisecond),
	}
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cancelWatchdog := StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
	})

	// Disarm before the timer would fire — mirrors the on-connect-success
	// path that races against the watchdog.
	time.Sleep(20 * time.Millisecond)
	cancelWatchdog()

	time.Sleep(400 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatalf("watchdog fired despite cancel: count=%d", fired.Load())
	}
}

func TestStartWatchdog_StopsOnContextCancel(t *testing.T) {
	setupTempDataDir(t)

	st := &PendingState{
		BackupConfPath: "/tmp/whatever",
		NewURL:         "https://b.example.com",
		ExpiresAt:      time.Now().Add(2 * time.Second),
	}
	if err := WritePending(st); err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	_ = StartWatchdog(ctx, st, func(_ *PendingState) {
		fired.Add(1)
	})

	cancel()
	time.Sleep(2500 * time.Millisecond)

	if fired.Load() != 0 {
		t.Fatalf("watchdog fired after ctx cancel: count=%d", fired.Load())
	}
}
