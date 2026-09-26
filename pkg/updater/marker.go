package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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
// It also treats that directory as secured, standing in for the Windows ACL
// step that tests do not run.
func OverrideMarkerDir(dir string) (restore func()) {
	prev := markerDirFn.Load()
	prevSecure := stateDirSecureFn
	markerDirFn.Store(func() string { return dir })
	stateDirSecureFn = func() bool { return true }
	return func() {
		markerDirFn.Store(prev)
		stateDirSecureFn = prevSecure
	}
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
	// RollbackAttempts counts failed in-process rollbacks.
	RollbackAttempts int `json:"rollback_attempts,omitempty"`

	// Note is carried into the final report's detail.
	Note string `json:"note,omitempty"`
}

var (
	guardUnitRe = regexp.MustCompile(`^alpamon-upgrade-guard-\d+$`)
	// PackageVersionRe bounds a package version before it becomes an
	// install argument or part of the guard script.
	PackageVersionRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~:-]*$`)
)

const maxMarkerTextLen = 512

// maxMarkerSize bounds how much of a marker file is read.
const maxMarkerSize = 64 * 1024

// maxMarkerSpan bounds deadline minus start: the longest package install
// window, the restart delay and the longest grace, with room to spare.
const maxMarkerSpan = 2 * time.Hour

// binaryPathFn is the running binary's path, the only binary a marker may
// name. A variable so tests can point it at a stand-in.
var binaryPathFn = func() (string, error) { return currentBinaryPath(Options{}) }

// validatePending checks every field the marker's readers act on, so a marker
// that this agent did not write for this host is never acted on.
func validatePending(p *PendingUpgrade) error {
	for name, v := range map[string]string{"from_version": p.FromVersion, "to_version": p.ToVersion} {
		if _, err := NormalizeTag(v); err != nil || strings.HasPrefix(v, " ") || strings.HasSuffix(v, " ") {
			return fmt.Errorf("%s %q is not a release version", name, v)
		}
	}
	if len(p.AttemptID) > maxMarkerTextLen || len(p.RollbackDetail) > 4*maxMarkerTextLen || len(p.Note) > maxMarkerTextLen {
		return errors.New("text field too long")
	}
	if p.StartedAt.IsZero() || !p.Deadline.After(p.StartedAt) || p.Deadline.Sub(p.StartedAt) > maxMarkerSpan {
		return fmt.Errorf("deadline %s does not follow start %s within %s", p.Deadline, p.StartedAt, maxMarkerSpan)
	}
	if p.RollbackAttempts < 0 || p.RollbackAttempts > maxRollbackAttempts {
		return fmt.Errorf("rollback attempts %d out of range", p.RollbackAttempts)
	}
	if p.GuardUnit != "" && !guardUnitRe.MatchString(p.GuardUnit) {
		return fmt.Errorf("guard unit %q is not an upgrade guard", p.GuardUnit)
	}
	switch p.RollbackClass {
	case "", ClassHealthCheckFailed:
	default:
		return fmt.Errorf("unexpected rollback class %q", p.RollbackClass)
	}

	switch p.Method {
	case MethodBinary:
		current, err := binaryPathFn()
		if err != nil {
			return err
		}
		if p.BinaryPath != current {
			return fmt.Errorf("binary path %q is not the running binary", p.BinaryPath)
		}
		if p.RollbackPath != current+rollbackSuffix {
			return fmt.Errorf("rollback path %q is not beside the running binary", p.RollbackPath)
		}
		if p.PackageManager != "" || p.PreviousPackageVersion != "" {
			return errors.New("binary marker carries package fields")
		}
	case MethodPackage:
		if p.PackageManager != utils.PackageManager {
			return fmt.Errorf("package manager %q is not this host's", p.PackageManager)
		}
		if !PackageVersionRe.MatchString(p.PreviousPackageVersion) {
			return fmt.Errorf("previous package version %q is not a package version", p.PreviousPackageVersion)
		}
		if p.BinaryPath != "" || p.RollbackPath != "" {
			return errors.New("package marker carries binary paths")
		}
	default:
		return fmt.Errorf("unknown upgrade method %q", p.Method)
	}
	return nil
}

// LoadPending reads the marker; (nil, nil) means no upgrade is in flight. A
// marker that fails validation, or that a non-administrative account owns, is
// logged, removed and treated as absent.
func LoadPending() (*PendingUpgrade, error) {
	path := MarkerPath()
	var p PendingUpgrade
	data, err := readStateFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&p); err != nil {
			err = fmt.Errorf("parse: %w", err)
		} else if _, extra := dec.Token(); extra != io.EOF {
			err = errors.New("trailing data after the marker object")
		}
	}
	if err == nil {
		err = validatePending(&p)
	}
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Discarding an invalid upgrade marker.")
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove invalid upgrade marker: %w", rmErr)
		}
		return nil, nil
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
	if err := validatePending(p); err != nil {
		return fmt.Errorf("refusing to write an invalid upgrade marker: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSynced(MarkerPath(), data, 0600)
}

// ClearPending removes the marker, and any guard result beside it.
// Idempotent.
func ClearPending() error {
	if err := os.Remove(MarkerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(guardResultPath())
	return nil
}

// writeFileSynced writes through a randomly named temp file created
// exclusively in the target directory, so nothing placed there beforehand is
// written through or renamed into place.
func writeFileSynced(path string, content []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		_ = os.Remove(tmp)
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
	return syncDir(filepath.Dir(path))
}

// syncDir persists the latest rename in dir. Windows cannot fsync a
// directory, so there the error is only logged; elsewhere it is returned,
// since a rename that is not durable can lose the marker in a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err == nil {
		err = d.Sync()
		_ = d.Close()
	}
	if err != nil && runtime.GOOS == "windows" {
		log.Debug().Err(err).Str("dir", dir).Msg("Directory fsync not supported; continuing.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
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
	return syncDir(filepath.Dir(dst))
}
