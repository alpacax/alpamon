package updater

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultHealthGrace applies when the console sends no grace period.
	DefaultHealthGrace = 5 * time.Minute
	minHealthGrace     = 1 * time.Minute
	maxHealthGrace     = 30 * time.Minute

	// RestartDelay is how long after the swap the service manager restarts
	// the agent, long enough for the command result to reach the console.
	RestartDelay = 5 * time.Second

	// guardMargin is how long after the deadline the guard fires, so the new
	// process's own rollback, which starts at the deadline, runs first.
	guardMargin = 2 * time.Minute

	rollbackSuffix = ".rollback"
)

// ErrUpgradePending is returned when a pinned upgrade is still waiting for
// the new version to confirm its health.
var ErrUpgradePending = errors.New("a previous upgrade is still being confirmed")

// ClampHealthGrace applies the default and the bounds to a requested grace.
func ClampHealthGrace(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultHealthGrace
	}
	return min(max(d, minHealthGrace), maxHealthGrace)
}

// staleMarkerAge is how long past its deadline a marker is trusted. A marker
// older than that was left by a process that never resumed it (a build
// without this code, say) and would otherwise block every later upgrade.
const staleMarkerAge = 1 * time.Hour

// CheckNoPending returns ErrUpgradePending while another attempt is in
// flight, and ErrStateDirInsecure when the directory holding the marker could
// not be secured. A marker long past its deadline is discarded instead of
// blocking.
func CheckNoPending(sm ServiceManager, now time.Time) error {
	if !stateDirSecureFn() {
		return ErrStateDirInsecure
	}
	existing, err := LoadPending()
	if err != nil || existing == nil {
		return err
	}
	if now.Before(existing.Deadline.Add(staleMarkerAge)) {
		return fmt.Errorf("%w (attempt %q to %s)", ErrUpgradePending, existing.AttemptID, existing.ToVersion)
	}
	log.Warn().Str("attempt_id", existing.AttemptID).Time("deadline", existing.Deadline).
		Msg("Discarding an upgrade marker long past its deadline.")
	_ = sm.DisarmGuard(existing.GuardUnit)
	return ClearPending()
}

// ErrStateDirInsecure is returned when the agent could not restrict access
// to the directory holding upgrade state, so none is written or acted on.
var ErrStateDirInsecure = errors.New("the agent's data directory could not be secured; pinned upgrades are disabled")

// stateDirSecureFn reports whether the data directory's access is restricted.
// A variable so tests can stand in for the Windows ACL step.
var stateDirSecureFn = utils.ConfigDirSecured

// BeginTransition records p as the intent marker and arms its guard, both
// before anything changes. settle is how long the change itself may take
// before the restart (a package install; zero for a binary swap): the
// deadline and the guard start counting only after it. The returned abort
// undoes the marker, the guard and the rollback copy, for a change that did
// not happen.
//
// A host with no service manager gets no guard; the new process's own health
// check is then the only way back.
func BeginTransition(p *PendingUpgrade, sm ServiceManager, settle, grace time.Duration, now time.Time) (abort func(), err error) {
	if err := CheckNoPending(sm, now); err != nil {
		return nil, err
	}

	p.StartedAt = now.UTC()
	if err := armGuard(p, sm, settle+RestartDelay+grace, now); err != nil {
		_ = ClearPending()
		return nil, err
	}

	abort = func() {
		_ = sm.DisarmGuard(p.GuardUnit)
		if err := ClearPending(); err != nil {
			log.Warn().Err(err).Msg("Failed to clear the upgrade marker.")
		}
		removeRollbackCopy(p)
	}
	return abort, nil
}

// Rearm restarts the clock once a slow change (a package install) is done:
// the deadline becomes grace from now and the guard is replaced by one that
// fires guardMargin after it.
//
// If the new guard cannot be armed, the marker is put back as it was, so the
// first guard, which is still scheduled, keeps covering the attempt.
func Rearm(p *PendingUpgrade, sm ServiceManager, grace time.Duration, now time.Time) error {
	saved := *p
	if err := armGuard(p, sm, RestartDelay+grace, now); err != nil {
		*p = saved
		if werr := WritePending(p); werr != nil {
			return errors.Join(err, fmt.Errorf("restore upgrade marker: %w", werr))
		}
		return err
	}
	_ = sm.DisarmGuard(saved.GuardUnit)
	return nil
}

// armGuard sets p's deadline to now+untilDeadline, names a fresh guard unit,
// writes the marker and then arms the guard. The guard acts only on a marker
// that names its own unit, so a guard left over from an earlier arming never
// acts on this one. On failure the marker is left as written; the caller
// decides whether to clear or restore it.
func armGuard(p *PendingUpgrade, sm ServiceManager, untilDeadline time.Duration, now time.Time) error {
	p.Deadline = now.UTC().Add(untilDeadline)
	p.GuardUnit = fmt.Sprintf("alpamon-upgrade-guard-%d", now.UnixNano())
	script, err := guardScript(p)
	if err != nil {
		return err
	}
	if err := WritePending(p); err != nil {
		return fmt.Errorf("write upgrade marker: %w", err)
	}

	if err := sm.ArmGuard(p.GuardUnit, untilDeadline+guardMargin, script); err != nil {
		if !errors.Is(err, ErrNoServiceManager) {
			return fmt.Errorf("arm upgrade guard: %w", err)
		}
		log.Warn().Msg("No service manager to arm an upgrade guard; relying on the new version's own health check.")
		p.GuardUnit = ""
		if err := WritePending(p); err != nil {
			return fmt.Errorf("write upgrade marker: %w", err)
		}
	}
	return nil
}

// stageRollbackCopy keeps the outgoing binary beside the live one, fsynced,
// until the new version proves healthy.
func stageRollbackCopy(currentPath string) (string, error) {
	info, err := os.Stat(currentPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat current binary: %w", err)
	}
	rollbackPath := currentPath + rollbackSuffix
	if err := copyFileSynced(currentPath, rollbackPath, info.Mode().Perm()); err != nil {
		_ = os.Remove(rollbackPath)
		return "", fmt.Errorf("failed to keep a rollback copy: %w", err)
	}
	return rollbackPath, nil
}

func removeRollbackCopy(p *PendingUpgrade) {
	if p.RollbackPath == "" {
		return
	}
	if err := os.Remove(p.RollbackPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warn().Err(err).Str("path", p.RollbackPath).Msg("Failed to remove the rollback copy.")
	}
}

func versionsEqual(a, b string) bool {
	return a != "" && strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}
