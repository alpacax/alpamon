package updater

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// scmServiceName must match serviceName in cmd/alpamon/command/register;
// copied because importing a cmd package from pkg would invert layering.
const scmServiceName = "alpamon"

// Recovery defaults applied by 'alpamon register'; copies for the same
// layering reason as scmServiceName.
const (
	recoveryResetSeconds = 60
	recoveryRestartDelay = 5 * time.Second
)

// ensureSelfRestartable verifies something will relaunch alpamon after the
// self-update exits: under SCM the first recovery action must be a restart,
// or the replaced binary dies unrelaunched and a remote-only server goes
// unreachable. A missing restart action is self-healed with register's
// defaults, trusting only a confirming re-query; any failure aborts
// (fail-closed). Preflight only: a later config change or a recent failure
// streak (SCM steps to later actions) can still leave the service stopped.
func ensureSelfRestartable() error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return abortf("failed to determine service mode: %w", err)
	}
	if !isSvc {
		// Interactive mode restarts itself via exec.Command (restartAgent).
		return nil
	}

	m, err := mgr.Connect()
	if err != nil {
		return abortf("failed to connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(scmServiceName)
	if err != nil {
		return abortf("failed to open service %q: %w", scmServiceName, err)
	}
	defer func() { _ = s.Close() }()

	return ensureRecoveryRestart(s)
}

// recoveryConfigurer is the subset of *mgr.Service that ensureRecoveryRestart
// needs; an interface so the self-heal path is unit-testable without a live SCM.
type recoveryConfigurer interface {
	RecoveryActions() ([]mgr.RecoveryAction, error)
	SetRecoveryActions(actions []mgr.RecoveryAction, resetPeriod uint32) error
}

// ensureRecoveryRestart passes when rc's first recovery action is a restart,
// otherwise self-heals register's defaults and trusts only a confirming
// re-query. Any SCM error aborts (fail-closed).
func ensureRecoveryRestart(rc recoveryConfigurer) error {
	actions, err := rc.RecoveryActions()
	if err != nil {
		return abortf("failed to query recovery actions: %w", err)
	}
	if firstActionRestarts(actions) {
		return nil
	}

	// Not a new policy: register already applies exactly this configuration.
	log.Warn().Msg("SCM recovery actions missing; restoring the defaults set by 'alpamon register'.")
	defaults := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: recoveryRestartDelay},
		{Type: mgr.ServiceRestart, Delay: recoveryRestartDelay},
		{Type: mgr.NoAction},
	}
	if err := rc.SetRecoveryActions(defaults, recoveryResetSeconds); err != nil {
		return abortf("automatic restart is not configured and restoring it failed: %w; run 'alpamon register' to configure it", err)
	}

	actions, err = rc.RecoveryActions()
	if err != nil {
		return abortf("failed to verify restored recovery actions: %w", err)
	}
	if !firstActionRestarts(actions) {
		return abortf("automatic restart is still not configured after restoring defaults; run 'alpamon register' to configure it")
	}
	log.Info().Msg("SCM recovery actions restored and verified.")
	return nil
}

func abortf(format string, args ...any) error {
	return fmt.Errorf("self-update aborted: "+format, args...)
}

// firstActionRestarts reports whether the first recovery action is a
// restart—SCM applies element [N-1] on the Nth failure, and the self-update
// exit is failure 1 in steady state.
func firstActionRestarts(actions []mgr.RecoveryAction) bool {
	return len(actions) > 0 && actions[0].Type == mgr.ServiceRestart
}
