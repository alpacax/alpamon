package updater

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// ErrNoServiceManager means the host has no service manager alpamon can ask
// to restart it from outside its own process, or to run a guard later.
var ErrNoServiceManager = errors.New("no supported service manager")

// ServiceManager schedules work that has to happen outside the agent process:
// the restart after an upgrade, and the guard that restores the previous
// version if the new one never confirms it is healthy.
type ServiceManager interface {
	// ScheduleRestart restarts the alpamon service after delay.
	ScheduleRestart(delay time.Duration) error
	// ArmGuard runs script as root after delay under the given unit name.
	ArmGuard(unit string, delay time.Duration, script string) error
	// DisarmGuard cancels a guard armed earlier. If the guard has already
	// started, it is left to finish, DisarmGuard waits for it, and fired is
	// true: the guard has then restored the previous version itself.
	DisarmGuard(unit string) (fired bool)
}

// DefaultServiceManager returns systemd when it runs as PID 1, and otherwise a
// manager that reports ErrNoServiceManager for every call.
func DefaultServiceManager() ServiceManager {
	if utils.HasSystemd() {
		return &systemdManager{run: runCombined, sleep: time.Sleep}
	}
	return noServiceManager{}
}

type noServiceManager struct{}

func (noServiceManager) ScheduleRestart(time.Duration) error          { return ErrNoServiceManager }
func (noServiceManager) ArmGuard(string, time.Duration, string) error { return ErrNoServiceManager }
func (noServiceManager) DisarmGuard(string) bool                      { return false }

// commandRunner runs a program and returns its combined output.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func runCombined(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

const systemdCallTimeout = 30 * time.Second

// systemdManager schedules transient timers with systemd-run. The units are
// owned by PID 1, so they outlive the alpamon service cgroup they are about
// to restart.
type systemdManager struct {
	run   commandRunner
	sleep func(time.Duration)
}

func (m *systemdManager) ScheduleRestart(delay time.Duration) error {
	unit := fmt.Sprintf("alpamon-upgrade-restart-%d", time.Now().UnixNano())
	return m.schedule(unit, delay, "systemctl", "restart", "alpamon")
}

func (m *systemdManager) ArmGuard(unit string, delay time.Duration, script string) error {
	return m.schedule(unit, delay, "/bin/sh", "-c", script)
}

// guardWaitMax bounds how long DisarmGuard waits for a running guard; a
// package reinstall is the slowest thing it does.
const guardWaitMax = 30 * time.Minute

func (m *systemdManager) DisarmGuard(unit string) bool {
	if unit == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemdCallTimeout)
	defer cancel()
	// Only the timer: stopping a guard that has started could kill a package
	// transaction halfway. A running guard is waited out instead.
	if out, err := m.run(ctx, "systemctl", "stop", unit+".timer"); err != nil {
		log.Debug().Err(err).Str("unit", unit).Msgf("Could not stop the upgrade guard timer: %s", strings.TrimSpace(string(out)))
	}
	fired := false
	for deadline := time.Now().Add(guardWaitMax); m.guardActive(unit) && time.Now().Before(deadline); {
		if !fired {
			log.Warn().Str("unit", unit).Msg("The upgrade guard is already running; waiting for it to finish.")
		}
		fired = true
		m.sleep(guardPollInterval)
	}
	_, _ = m.run(ctx, "systemctl", "reset-failed", unit+".timer", unit+".service")
	return fired
}

const guardPollInterval = 2 * time.Second

func (m *systemdManager) guardActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), systemdCallTimeout)
	defer cancel()
	out, err := m.run(ctx, "systemctl", "is-active", unit+".service")
	if err != nil {
		return false
	}
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "deactivating", "reloading":
		return true
	}
	return false
}

func (m *systemdManager) schedule(unit string, delay time.Duration, command ...string) error {
	secs := max(int(delay.Seconds()), 1)
	args := []string{
		fmt.Sprintf("--on-active=%ds", secs),
		// The default AccuracySec of one minute would let systemd fire late.
		"--timer-property=AccuracySec=1s",
		"--unit", unit,
	}
	args = append(args, command...)

	ctx, cancel := context.WithTimeout(context.Background(), systemdCallTimeout)
	defer cancel()
	// --collect needs systemd 236; SLES 12 ships 228, so retry without it.
	out, err := m.run(ctx, "systemd-run", append([]string{"--collect"}, args...)...)
	if err != nil {
		out, err = m.run(ctx, "systemd-run", args...)
	}
	if err != nil {
		return fmt.Errorf("systemd-run %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}

// guardScript is what the guard runs if the deadline passes with the marker
// still present. It only restores: the process that starts afterwards finds
// the marker, sees it is the previous version, and reports the rollback.
//
// It acts only while the marker still names this guard's unit, so a guard
// whose disarm failed never acts on a later arming or attempt.
func guardScript(p *PendingUpgrade) (string, error) {
	marker := shellQuote(MarkerPath())
	// The exact "guard_unit" line MarshalIndent writes, so a unit name that
	// appears in another field cannot match.
	pending := fmt.Sprintf("[ -f %s ] && grep -qxF %s %s", marker, shellQuote(`  "guard_unit": "`+p.GuardUnit+`",`), marker)
	switch p.Method {
	case MethodBinary:
		return fmt.Sprintf("if %s && [ -f %s ]; then mv -f %s %s && systemctl restart alpamon; fi",
			pending, shellQuote(p.RollbackPath), shellQuote(p.RollbackPath), shellQuote(p.BinaryPath)), nil
	case MethodPackage:
		argv, err := PackageRollbackCommand(p.PackageManager, p.PreviousPackageVersion, p.ToVersion)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("if %s; then %s && systemctl restart alpamon; fi", pending, shellJoin(argv)), nil
	}
	return "", fmt.Errorf("unknown upgrade method %q", p.Method)
}

// PackageRollbackCommand is the pinned reinstall of the outgoing version
// previous over current. apt and zypper take either direction with one
// command; yum needs downgrade or install depending on which is newer.
func PackageRollbackCommand(packageManager, previous, current string) ([]string, error) {
	if !PackageVersionRe.MatchString(previous) {
		return nil, fmt.Errorf("previous package version %q is not usable", previous)
	}
	switch packageManager {
	case utils.PkgApt:
		return []string{"apt-get", "install", "-y", "--allow-downgrades", "alpamon=" + previous}, nil
	case utils.PkgYum:
		verb := "downgrade"
		if CompareVersions(previous, current) > 0 {
			verb = "install"
		}
		return []string{"yum", verb, "-y", "alpamon-" + previous}, nil
	case utils.PkgZypper:
		return []string{"zypper", "--non-interactive", "install", "--oldpackage", "alpamon=" + previous}, nil
	}
	return nil, fmt.Errorf("package manager %q cannot roll back", packageManager)
}
