package updater

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

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

// BeginTransition records p as the intent marker and arms its guard, both
// before anything changes. It fills in the timestamps and guard unit. The
// returned abort undoes both, and removes the rollback copy, for a swap that
// failed before the restart.
//
// A host with no service manager gets no guard; the new process's own health
// check is then the only way back.
func BeginTransition(p *PendingUpgrade, sm ServiceManager, grace time.Duration, now time.Time) (abort func(), err error) {
	existing, err := LoadPending()
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("%w (attempt %q to %s)", ErrUpgradePending, existing.AttemptID, existing.ToVersion)
	}

	script, err := guardScript(p)
	if err != nil {
		return nil, err
	}
	p.StartedAt = now.UTC()
	p.Deadline = p.StartedAt.Add(RestartDelay + grace)
	p.GuardUnit = fmt.Sprintf("alpamon-upgrade-guard-%d", now.UnixNano())
	if err := WritePending(p); err != nil {
		return nil, fmt.Errorf("write upgrade marker: %w", err)
	}

	if err := sm.ArmGuard(p.GuardUnit, RestartDelay+grace+guardMargin, script); err != nil {
		if !errors.Is(err, ErrNoServiceManager) {
			_ = ClearPending()
			return nil, fmt.Errorf("arm upgrade guard: %w", err)
		}
		log.Warn().Msg("No service manager to arm an upgrade guard; relying on the new version's own health check.")
		p.GuardUnit = ""
		if err := WritePending(p); err != nil {
			_ = ClearPending()
			return nil, fmt.Errorf("write upgrade marker: %w", err)
		}
	}

	abort = func() {
		sm.DisarmGuard(p.GuardUnit)
		if err := ClearPending(); err != nil {
			log.Warn().Err(err).Msg("Failed to clear the upgrade marker.")
		}
		removeRollbackCopy(p)
	}
	return abort, nil
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
