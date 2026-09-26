package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

const markerFilename = "upgrade.pending"

// Upgrade methods recorded in the marker.
const (
	MethodBinary  = "binary"
	MethodPackage = "package"
)

// markerDirFn resolves the directory holding the marker. Atomic because tests
// swap it while a resumed health check may still be reading it.
var markerDirFn atomic.Value

func init() {
	markerDirFn.Store(func() string { return utils.DataDir() })
}

// OverrideMarkerDir points the marker at dir until the returned restore runs.
// Tests only.
func OverrideMarkerDir(dir string) (restore func()) {
	prev := markerDirFn.Load()
	markerDirFn.Store(func() string { return dir })
	return func() { markerDirFn.Store(prev) }
}

// MarkerPath is where an in-flight pinned upgrade records its intent.
func MarkerPath() string {
	return filepath.Join(markerDirFn.Load().(func() string)(), markerFilename)
}

// PendingUpgrade is the intent marker. It is written and fsynced before the
// binary or package changes, and read by whichever process starts next.
type PendingUpgrade struct {
	AttemptID   string `json:"attempt_id"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Method      string `json:"method"`

	// MethodBinary: the live binary and the copy of the outgoing one.
	BinaryPath   string `json:"binary_path,omitempty"`
	RollbackPath string `json:"rollback_path,omitempty"`

	// MethodPackage: how to reinstall the outgoing version.
	PackageManager         string `json:"package_manager,omitempty"`
	PreviousPackageVersion string `json:"previous_package_version,omitempty"`

	// GuardUnit names the scheduled guard, empty when none could be armed.
	GuardUnit string    `json:"guard_unit,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Deadline  time.Time `json:"deadline"`

	// Set by a process that rolled back, for the one that starts after it.
	RollbackClass  ErrorClass `json:"rollback_class,omitempty"`
	RollbackDetail string     `json:"rollback_detail,omitempty"`
}

// LoadPending reads the marker; (nil, nil) means no upgrade is in flight.
func LoadPending() (*PendingUpgrade, error) {
	data, err := os.ReadFile(MarkerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read upgrade marker: %w", err)
	}
	var p PendingUpgrade
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse upgrade marker: %w", err)
	}
	return &p, nil
}

// WritePending persists the marker durably: temp file, fsync, rename, then
// fsync of the directory, so a crash never leaves a partial marker.
func WritePending(p *PendingUpgrade) error {
	dir := filepath.Dir(MarkerPath())
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("ensure marker dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSynced(MarkerPath(), data, 0600)
}

// ClearPending removes the marker. Idempotent.
func ClearPending() error {
	if err := os.Remove(MarkerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeFileSynced(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir persists the latest rename in dir. Windows cannot fsync a
// directory; the rename is still durable there once MoveFileEx returns.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		log.Debug().Err(err).Str("dir", dir).Msg("Directory fsync not supported; continuing.")
	}
}

// copyFileSynced copies src to dst and fsyncs dst before returning.
func copyFileSynced(src, dst string, perm os.FileMode) error {
	if err := copyFile(src, dst, perm); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return err
	}
	syncDir(filepath.Dir(dst))
	return nil
}
