package updater

import (
	"fmt"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/svcdef"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// maxAcceptableRestartDelay bounds how long the server may stay unreachable after
// the self-update exit; a slower restart is healed to register's defaults, not trusted.
const maxAcceptableRestartDelay = 60 * time.Second

// recoveryConfigurer is the subset of *mgr.Service ensureRecoveryRestart needs,
// an interface so the self-heal path is testable without a live SCM.
type recoveryConfigurer interface {
	RecoveryActions() ([]mgr.RecoveryAction, error)
	SetRecoveryActions(actions []mgr.RecoveryAction, resetPeriod uint32) error
}

// ensureSelfRestartable aborts the self-update unless a relaunch is guaranteed
// afterward—otherwise the replaced binary stays dead and a remote-only server
// goes unreachable. Preflight only: config drift or a failure streak past the
// first action can still leave the service stopped—permanently so when the reset
// period is INFINITE, since the failure count never ages out and the third update
// lands on NoAction. Undetectable here: mgr.RecoveryActions() omits the reset period.
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

// ensureRecoveryRestart passes when rc's first recovery action is a prompt
// restart, otherwise self-heals register's defaults and trusts only a confirming
// re-query. Any SCM error aborts (fail-closed).
func ensureRecoveryRestart(rc recoveryConfigurer) error {
	actions, err := rc.RecoveryActions()
	if err != nil {
		return abortf("failed to query recovery actions: %w", err)
	}
	if firstActionRestarts(actions) {
		return nil
	}

	// register already applies exactly this config, but SetRecoveryActions replaces
	// the whole array—record what's lost, since this log is the only way back.
	log.Warn().Strs("replaced", describeActions(actions)).
		Msg("First SCM recovery action is not a prompt restart; restoring the defaults set by 'alpamon register'.")
	defaults := svcdef.DefaultRecoveryActions()
	if err := rc.SetRecoveryActions(defaults, svcdef.RecoveryResetSeconds); err != nil {
		return abortf("a prompt automatic restart is not configured and restoring it failed: %w; run 'alpamon register' to configure it", err)
	}

	actions, err = rc.RecoveryActions()
	if err != nil {
		return abortf("failed to verify restored recovery actions: %w", err)
	}
	if !firstActionRestarts(actions) {
		return abortf("a prompt automatic restart is still not configured after restoring defaults; run 'alpamon register' to configure it")
	}
	log.Info().Msg("SCM recovery actions restored and verified.")
	return nil
}

// abortf formats a fail-closed reason under the shared "self-update aborted" prefix.
func abortf(format string, args ...any) error {
	return fmt.Errorf("self-update aborted: "+format, args...)
}

// describeActions renders recovery actions for the overwrite log; mgr encodes
// RecoveryAction.Type as a bare int that means nothing to a reader.
func describeActions(actions []mgr.RecoveryAction) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		var name string
		switch a.Type {
		case mgr.NoAction:
			name = "none"
		case mgr.ComputerReboot:
			name = "reboot"
		case mgr.ServiceRestart:
			name = "restart"
		case mgr.RunCommand:
			name = "run-command"
		default:
			name = fmt.Sprintf("unknown(%d)", a.Type)
		}
		out[i] = fmt.Sprintf("%s after %s", name, a.Delay)
	}
	return out
}

// firstActionRestarts reports whether the first recovery action restarts the
// service soon enough to count as a guarantee—SCM applies element [N-1] on the
// Nth failure, and the self-update exit is failure 1 in steady state.
func firstActionRestarts(actions []mgr.RecoveryAction) bool {
	return len(actions) > 0 &&
		actions[0].Type == mgr.ServiceRestart &&
		actions[0].Delay <= maxAcceptableRestartDelay
}
