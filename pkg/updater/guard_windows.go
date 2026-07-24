package updater

import (
	"fmt"

	"github.com/alpacax/alpamon/v2/pkg/svcdef"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// recoveryConfigurer is the subset of *mgr.Service ensureRecoveryRestart needs,
// an interface so the self-heal path is testable without a live SCM.
type recoveryConfigurer interface {
	RecoveryActions() ([]mgr.RecoveryAction, error)
	SetRecoveryActions(actions []mgr.RecoveryAction, resetPeriod uint32) error
}

// ensureSelfRestartable aborts the self-update unless a relaunch is guaranteed
// afterward—otherwise the replaced binary stays dead and a remote-only server
// goes unreachable. Preflight only: config drift or a failure streak past the
// first action can still leave the service stopped.
func ensureSelfRestartable() error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		// Deliberately stricter than runningAsWindowsService(), which assumes
		// interactive on this error: guessing interactive on a real service would
		// skip the restart check and leave the replaced binary with nothing to relaunch it.
		return abortf("failed to determine service mode: %w", err)
	}
	if !isSvc {
		return nil
	}

	m, err := mgr.Connect()
	if err != nil {
		return abortf("failed to connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(svcdef.ServiceName)
	if err != nil {
		return abortf("failed to open service %q: %w", svcdef.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	return ensureRecoveryRestart(s)
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
	defaults := svcdef.DefaultRecoveryActions()
	if err := rc.SetRecoveryActions(defaults, svcdef.RecoveryResetSeconds); err != nil {
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
