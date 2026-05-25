// Package migrate handles workspace migration for alpamon.
//
// Migration moves an in-place alpamon agent from one Alpacon workspace to
// another while preserving the only access channel (the WebSocket back to
// Alpacon). The flow is split into three pieces:
//
//  1. The `alpamon migrate` subcommand (in cmd/alpamon/command/migrate)
//     calls the target workspace's register API, atomically swaps
//     /etc/alpamon/alpamon.conf, writes a marker file, and schedules a
//     transient systemd timer to `systemctl restart alpamon` shortly after.
//
//  2. On the next startup the agent (root.go) loads the marker file. If
//     present, it arms a watchdog and registers a connect-success hook on
//     the WebSocket client. Confirm() clears the marker on the first
//     successful auth handshake.
//
//  3. If the watchdog timer elapses without Confirm() having fired (i.e.
//     the new workspace never accepted the agent), Rollback() restores the
//     backup config, best-effort unregisters the orphan record on the
//     target workspace, and schedules another self-restart. The agent comes
//     back up on the original workspace.
//
// All durable state is committed in a strict order so that a crash anywhere
// in the sequence is recoverable on the next startup:
//
//	BackupConf  →  WritePending  →  WriteConfAtomic  →  ScheduleSelfRestart
//
// If we die after BackupConf but before WritePending: an orphan .bak file
// lingers, no behavior change. If we die after WritePending but before the
// conf swap: the marker points at a backup that matches the running conf;
// the next watchdog tick restores it (no-op) and clears the marker. If we
// die after the conf swap but before scheduling the restart: the agent
// continues running with the old conf in memory, but the next restart
// (manual or otherwise) picks up the new conf and the watchdog protects us
// either way.
package migrate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// DefaultRollbackTimeout is the default deadline for the post-migration
// watchdog. Tuned long enough to absorb transient network hiccups during
// the first reconnect, short enough that a stuck migration recovers before
// an operator gives up and pages someone.
const DefaultRollbackTimeout = 5 * time.Minute

// MaxRollbackTimeout caps how long the marker file (which carries the new
// workspace's server key in plaintext) can sit on disk. Even though the
// same key is in /etc/alpamon/alpamon.conf during the same window, we
// don't want operators accidentally extending the on-disk lifetime to days
// via an inflated --rollback-timeout flag.
const MaxRollbackTimeout = 1 * time.Hour

const markerFilename = "migration.pending"

// dataDirFnAtom holds the function used to resolve the data directory.
// Stored atomically because tests swap it under setupTempDataDir while the
// watchdog goroutine (which calls dataDirFn() via MarkerPath/LoadPending)
// may still be running.
var dataDirFnAtom atomic.Value

func init() {
	dataDirFnAtom.Store(func() string { return utils.DataDir() })
}

func dataDirFn() string {
	return dataDirFnAtom.Load().(func() string)()
}

// PendingState describes an in-flight migration. It is persisted as JSON to
// MarkerPath() and read back on the next agent startup.
//
// NewServerKey is included so Rollback() can authenticate to the target
// workspace as the just-created server and delete the orphan record.
// Leaving the key on disk is acceptable here: the marker is in
// /var/lib/alpamon (mode 0750, root-owned), and the same key already lives
// in /etc/alpamon/alpamon.conf during the same window.
type PendingState struct {
	BackupConfPath string    `json:"backup_conf_path"`
	OldURL         string    `json:"old_url"`
	NewURL         string    `json:"new_url"`
	NewServerID    string    `json:"new_server_id"`
	NewServerKey   string    `json:"new_server_key"`
	StartedAt      time.Time `json:"started_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// MarkerPath returns the absolute path of the in-flight-migration marker.
func MarkerPath() string {
	return filepath.Join(dataDirFn(), markerFilename)
}

// LoadPending reads the marker file. Returns (nil, nil) when no migration
// is in flight.
func LoadPending() (*PendingState, error) {
	data, err := os.ReadFile(MarkerPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read marker: %w", err)
	}
	var st PendingState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse marker: %w", err)
	}
	return &st, nil
}

// WritePending persists the marker via temp + fsync + rename + dir-fsync
// so a power loss after rename never resurfaces a marker with partial
// contents.
func WritePending(st *PendingState) error {
	if err := os.MkdirAll(dataDirFn(), 0750); err != nil {
		return fmt.Errorf("ensure data dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal marker: %w", err)
	}
	return writeFileAtomic(MarkerPath(), data, 0600)
}

// ClearPending removes the marker file. Idempotent.
func ClearPending() error {
	if err := os.Remove(MarkerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Confirm finalizes a successful migration: removes the marker and the
// backup conf. Safe to call with a nil state. Logged failures are not
// surfaced because by the time Confirm runs, the WebSocket to the new
// workspace is up and there is no rollback path left.
func Confirm(st *PendingState) {
	if st == nil {
		return
	}
	if err := ClearPending(); err != nil {
		log.Warn().Err(err).Msg("Failed to clear migration marker after successful connect.")
	}
	if st.BackupConfPath != "" {
		if err := os.Remove(st.BackupConfPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn().Err(err).Str("path", st.BackupConfPath).Msg("Failed to remove migration backup conf.")
		}
	}
	log.Info().Str("new_url", st.NewURL).Msg("Workspace migration confirmed; new connection established.")
}

// BackupConf copies srcPath to a timestamped sibling and returns the
// backup path. The backup keeps the source's mode bits so a restore
// produces an identical file. Both the file contents and the parent
// directory entry are fsync'd so a power loss right after this call
// does not lose the backup.
func BackupConf(srcPath string) (string, error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("open source conf: %w", err)
	}
	defer func() { _ = in.Close() }()

	info, err := in.Stat()
	if err != nil {
		return "", fmt.Errorf("stat source conf: %w", err)
	}

	backup := fmt.Sprintf("%s.bak.%d", srcPath, time.Now().Unix())
	out, err := os.OpenFile(backup, os.O_CREATE|os.O_WRONLY|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return "", fmt.Errorf("create backup: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		_ = os.Remove(backup)
		return "", fmt.Errorf("copy backup: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = os.Remove(backup)
		return "", fmt.Errorf("sync backup: %w", err)
	}
	if err := fsyncDir(filepath.Dir(backup)); err != nil {
		log.Warn().Err(err).Msg("fsync of backup dir failed; backup file content is still synced.")
	}
	return backup, nil
}

// WriteConfAtomic writes content to confPath via writeFileAtomic. The
// parent directory is created with 0700 to mirror configs/tmpfile.conf,
// keeping the alpamon config dir confidential (it holds secrets).
func WriteConfAtomic(confPath string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(confPath), 0700); err != nil {
		return fmt.Errorf("ensure conf dir: %w", err)
	}
	return writeFileAtomic(confPath, content, mode)
}

// writeFileAtomic creates path with content via:
//
//	open(tmp) → write → fsync(tmp) → close → rename(tmp, path) → fsync(parent)
//
// Each step protects against a different failure mode: fsync(tmp) guards
// against partial-content rename, fsync(parent) guards against a vanished
// directory entry. Callers may rely on the file being durable as soon as
// this returns nil.
func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create tmp %s: %w", tmp, err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename tmp -> %s: %w", path, err)
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		log.Warn().Err(err).Msg("fsync of parent dir failed; rename is still durable on most filesystems.")
	}
	return nil
}

// fsyncDir opens dir read-only and fsyncs it so the latest rename(2) in
// that directory is persisted. On Windows os.File.Sync on a directory is
// a no-op; we let the error propagate so the caller can log it.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// RestoreBackup copies backupPath over destPath via WriteConfAtomic so the
// destination is updated atomically. The backup file's mode bits are
// preserved (rather than forced to 0600) so a rollback yields an identical
// file when the operator had previously set tighter or different
// permissions on the original conf.
func RestoreBackup(backupPath, destPath string) error {
	info, err := os.Stat(backupPath)
	if err != nil {
		return fmt.Errorf("stat backup: %w", err)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	return WriteConfAtomic(destPath, data, info.Mode().Perm())
}

// ScheduleSelfRestart asks systemd to run `systemctl restart alpamon`
// after the given delay via a transient timer unit. The transient unit is
// owned by systemd PID 1, so it survives the imminent restart of the
// alpamon.service cgroup (the unit that the migrate or rollback caller
// itself lives under).
//
// systemd is a hard requirement here: there is no portable way to ask a
// process tree we're about to be killed in to restart us from outside.
func ScheduleSelfRestart(delay time.Duration) error {
	if !utils.HasSystemd() {
		return errors.New("systemd is required for migrate self-restart")
	}
	if delay < time.Second {
		delay = time.Second
	}
	secs := int(delay.Seconds())
	unit := fmt.Sprintf("alpamon-restart-%d", time.Now().UnixNano())
	cmd := exec.Command("systemd-run",
		fmt.Sprintf("--on-active=%ds", secs),
		"--collect",
		"--unit", unit,
		"systemctl", "restart", "alpamon",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Rollback executes the recovery sequence: restore the backup config,
// best-effort unregister the orphan record on the target workspace,
// schedule a self-restart, and only then drop the marker + backup files.
// Returns an error if restoring the backup OR scheduling the restart
// fails; in either case the marker is intentionally left in place so the
// next agent startup retries via the watchdog.
//
// Ordering matters: the marker must outlive a failed ScheduleSelfRestart
// (otherwise the agent would be left running on the new conf with no
// retry handle). The backup is removed last so a partially-completed
// Rollback can re-run safely from the next startup.
//
// The function is idempotent: a missing backup file is treated as
// "already restored on a previous attempt".
func Rollback(state *PendingState, confPath string, sslVerify bool, caCertPath string) error {
	if state == nil {
		return errors.New("nil state")
	}

	log.Warn().
		Str("backup_conf", state.BackupConfPath).
		Str("conf_path", confPath).
		Str("new_url", state.NewURL).
		Msg("Migration watchdog: restoring previous configuration.")

	if _, statErr := os.Stat(state.BackupConfPath); statErr == nil {
		if err := RestoreBackup(state.BackupConfPath, confPath); err != nil {
			return fmt.Errorf("restore backup: %w", err)
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		log.Warn().Str("backup", state.BackupConfPath).
			Msg("Rollback: backup file missing; assuming a previous attempt restored it.")
	} else {
		return fmt.Errorf("stat backup: %w", statErr)
	}

	BestEffortUnregister(state.NewURL, state.NewServerID, state.NewServerKey, sslVerify, caCertPath)

	if err := ScheduleSelfRestart(2 * time.Second); err != nil {
		// Marker is intentionally still on disk so the next startup's
		// watchdog tries again. Don't touch backup either — we may need
		// it for the retry.
		return fmt.Errorf("schedule self-restart: %w", err)
	}

	// Now that the restart is queued, clear durable state. From here on,
	// even if the restart itself never fires, the agent is at worst
	// running on the (already restored) old conf without a marker — no
	// data loss.
	if state.BackupConfPath != "" {
		if err := os.Remove(state.BackupConfPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn().Err(err).Str("path", state.BackupConfPath).
				Msg("Failed to remove backup conf after rollback.")
		}
	}
	if err := ClearPending(); err != nil {
		log.Warn().Err(err).Msg("Failed to clear migration marker after rollback.")
	}

	log.Info().Msg("Migration rolled back; self-restart scheduled.")
	return nil
}

// StartWatchdog arms a goroutine that fires onTimeout when the marker's
// ExpiresAt elapses without the marker having been cleared. If the marker
// is already past its deadline (we crashed during a previous wait), the
// callback fires asynchronously right away.
//
// The returned cancel function disarms the watchdog. Callers MUST invoke
// it from the WebSocket connect-success path so a successful migration
// does not race against the timer firing the rollback (which would call
// the unregister endpoint against a now-live B-side server record). The
// fire path also re-loads the marker before invoking onTimeout to guard
// against the case where Confirm() ran between the timer firing and the
// callback entering.
func StartWatchdog(ctx context.Context, state *PendingState, onTimeout func(*PendingState)) context.CancelFunc {
	if state == nil {
		return func() {}
	}

	childCtx, cancel := context.WithCancel(ctx)

	remaining := time.Until(state.ExpiresAt)
	log.Info().
		Dur("timeout", remaining).
		Time("expires_at", state.ExpiresAt).
		Str("new_url", state.NewURL).
		Msg("Workspace migration pending; rollback watchdog armed.")

	fire := func(reason string) {
		// Cancel-vs-fire is racy at multiple points: between timer.C
		// firing and entering fire(), between LoadPending() and
		// onTimeout(). We check childCtx.Err() at both edges so a
		// Cancel that lands ANYWHERE before onTimeout takes effect.
		if childCtx.Err() != nil {
			return
		}
		cur, err := LoadPending()
		if err != nil {
			log.Warn().Err(err).Msg("Watchdog: failed to re-read marker; aborting fire.")
			return
		}
		if cur == nil {
			log.Info().Msg("Watchdog: migration confirmed before fire; nothing to do.")
			return
		}
		if childCtx.Err() != nil {
			log.Info().Msg("Watchdog: canceled during marker re-read; standing down.")
			return
		}
		log.Warn().Str("reason", reason).Msg("Watchdog: firing rollback.")
		onTimeout(cur)
	}

	if remaining <= 0 {
		go fire("marker already expired at startup")
		return cancel
	}

	go func() {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-childCtx.Done():
			return
		case <-timer.C:
			fire("rollback timeout elapsed")
		}
	}()
	return cancel
}

// BestEffortUnregister calls the target workspace's unregister endpoint as
// the just-created server. Used by Rollback (to remove the orphan record
// on the workspace we abandoned) and by the migrate subcommand's own
// error paths. Failures (network, auth, missing systemd, etc.) are logged
// but not surfaced — the caller is already on an error path.
//
// A short deadline is enforced so a hung B-side endpoint cannot stall
// rollback or block the operator's terminal.
func BestEffortUnregister(targetURL, serverID, serverKey string, sslVerify bool, caCertPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/servers/servers/%s/unregister/",
		strings.TrimSuffix(targetURL, "/"), serverID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Best-effort unregister: build request failed.")
		return
	}
	req.Header.Set("Authorization",
		fmt.Sprintf(`id="%s", key="%s"`, serverID, serverKey))

	client, err := newHTTPClient(sslVerify, caCertPath)
	if err != nil {
		log.Warn().Err(err).Msg("Best-effort unregister: build HTTP client failed.")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("Best-effort unregister: request failed.")
		return
	}
	defer func() {
		// Drain so the underlying connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode/100 != 2 {
		log.Warn().Int("status", resp.StatusCode).Msg("Best-effort unregister: non-2xx status.")
	}
}

func newHTTPClient(sslVerify bool, caCertPath string) (*http.Client, error) {
	cfg := &tls.Config{InsecureSkipVerify: !sslVerify}
	if caCertPath != "" {
		data, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid CA certificate")
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}, nil
}
