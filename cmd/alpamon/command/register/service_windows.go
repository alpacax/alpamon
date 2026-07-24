package register

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/svcdef"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceDisplayName = "Alpamon Agent"
	serviceDescription = "Secure server agent for the Alpacon infrastructure access platform."

	// serviceStopPoll* bound how long removeService waits for the SCM to report
	// the service Stopped before deleting it (15s total).
	serviceStopPollAttempts = 30
	serviceStopPollInterval = 500 * time.Millisecond
)

// defaultInstallBinPath returns the canonical SCM BinaryPathName that
// ensureInstalled() targets. Used as a fallback when os.Executable()
// fails; derived from installDir() so both the installer and the
// service entry stay in sync across systems where %ProgramFiles% is
// non-default (different drive / localized install).
func defaultInstallBinPath() string {
	return filepath.Join(installDir(), installExeName)
}

func ensureDirectories() error {
	return utils.EnsureDirectories()
}

func startService() error {
	binPath := defaultInstallBinPath()
	if exe, err := os.Executable(); err == nil {
		binPath = exe
	} else {
		fmt.Printf("Warning: os.Executable() failed (%v); falling back to %s\n", err, binPath)
	}
	// SCM stores BinaryPathName as a command line; a path that contains
	// whitespace must be quoted. Leaving it unquoted triggers the
	// classic "unquoted service path" behavior where Windows may
	// search and execute sibling files (C:\Program.exe, etc.).
	serviceBinPath := quoteServicePath(binPath)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w%s", err, elevationHint(err))
	}
	defer func() { _ = m.Disconnect() }()

	// If alpamon is already installed, reuse the existing service
	// entry rather than failing: operators commonly re-run register.
	// Only treat ERROR_SERVICE_DOES_NOT_EXIST as "go create it"; any
	// other OpenService failure (access denied, RPC issues) should
	// surface so the operator can address it.
	s, err := m.OpenService(svcdef.ServiceName)
	if err != nil {
		if !isServiceNotExist(err) {
			return fmt.Errorf("open service: %w%s", err, elevationHint(err))
		}
		s, err = m.CreateService(
			svcdef.ServiceName,
			serviceBinPath,
			mgr.Config{
				DisplayName:      serviceDisplayName,
				Description:      serviceDescription,
				StartType:        mgr.StartAutomatic,
				DelayedAutoStart: true,
				ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
				ErrorControl:     mgr.ErrorNormal,
			},
		)
		if err != nil {
			return fmt.Errorf("create service: %w%s", err, elevationHint(err))
		}

		// mgr.CreateService internally calls syscall.EscapeArg on
		// exepath, which sees our already-quoted serviceBinPath,
		// escapes the inner quotes as \", and wraps the whole thing
		// in another pair of "...". SCM stores that 42-character
		// value in ImagePath verbatim, then can't spawn it because
		// CommandLineToArgvW interprets \" as a literal quote in
		// argv[0]. Rewrite BinaryPathName via UpdateConfig (which
		// does not call EscapeArg) so the stored ImagePath ends up as
		// the canonical "<path>" command line.
		if err := normalizeServiceBinaryPath(s, serviceBinPath); err != nil {
			// Best-effort rollback: delete the freshly-created service
			// so a failed register does not leave a broken
			// (double-encoded) ImagePath entry behind. Close
			// explicitly afterward — the deferred close below has not
			// been registered yet at this point in the function flow.
			deleteErr := s.Delete()
			_ = s.Close()
			if deleteErr != nil {
				return fmt.Errorf("normalize service binary path: %w (rollback delete service: %v)%s", err, deleteErr, elevationHint(err))
			}
			return fmt.Errorf("normalize service binary path: %w%s", err, elevationHint(err))
		}
	} else {
		// Service already exists. Refresh its config so re-running
		// register is idempotent and corrects any drift: a binPath
		// pointing at an older location, services created by the old
		// sc.exe instructions without DelayedAutoStart, etc.
		if cfg, cfgErr := s.Config(); cfgErr == nil {
			cfg.BinaryPathName = serviceBinPath
			cfg.DisplayName = serviceDisplayName
			cfg.Description = serviceDescription
			cfg.StartType = mgr.StartAutomatic
			cfg.DelayedAutoStart = true
			cfg.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
			cfg.ErrorControl = mgr.ErrorNormal
			if err := s.UpdateConfig(cfg); err != nil {
				fmt.Printf("Warning: failed to refresh service configuration: %v\n", err)
			}
		} else {
			fmt.Printf("Warning: failed to read existing service configuration: %v\n", cfgErr)
		}
	}
	defer func() { _ = s.Close() }()

	// Auto-restart on crash. Use conservative delays so a broken
	// binary doesn't thrash SCM.
	recoveryActions := svcdef.DefaultRecoveryActions()
	if err := s.SetRecoveryActions(recoveryActions, svcdef.RecoveryResetSeconds); err != nil {
		// Non-fatal; log and continue. The service will still start,
		// just without automatic recovery.
		fmt.Printf("Warning: failed to configure service recovery actions: %v\n", err)
	}

	if err := s.Start(); err != nil {
		// ERROR_SERVICE_ALREADY_RUNNING (1056) is fine.
		if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_SERVICE_ALREADY_RUNNING {
			return nil
		}
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

func printManualStartHint() {
	fmt.Println("Please start alpamon manually:")
	fmt.Println("  sc.exe start alpamon")
}

// withService connects to the SCM, opens the alpamon service, runs fn against
// it, and closes both handles. A service that does not exist is treated as a
// no-op success so the teardown helpers never fail on an already-clean box.
// Requires Administrator (same as startService).
func withService(fn func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w%s", err, elevationHint(err))
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(svcdef.ServiceName)
	if err != nil {
		if isServiceNotExist(err) {
			return nil
		}
		return fmt.Errorf("open service: %w%s", err, elevationHint(err))
	}
	defer func() { _ = s.Close() }()

	return fn(s)
}

// stopService stops the alpamon SCM service without deleting it. Used by
// register --force to bounce a running service so it reloads the freshly
// written config (a delete+recreate would race the SCM with
// ERROR_SERVICE_MARKED_FOR_DELETE). Best-effort/idempotent.
func stopService() error {
	return withService(func(s *mgr.Service) error {
		stopRunningService(s)
		return nil
	})
}

// removeService stops and deletes the alpamon SCM service (full teardown for
// unregister). Best-effort/idempotent.
func removeService() error {
	return withService(func(s *mgr.Service) error {
		stopRunningService(s)
		if err := s.Delete(); err != nil {
			return fmt.Errorf("delete service: %w%s", err, elevationHint(err))
		}
		return nil
	})
}

// stopRunningService signals Stop and waits (best-effort) for the SCM to report
// Stopped so the binary handle is released. ERROR_SERVICE_NOT_ACTIVE (already
// stopped) is fine. The caller owns the handle. Errors are logged, not returned,
// because both callers are best-effort. The poll only returns early on a
// confirmed Stopped state—a transient Query error must NOT be mistaken for
// "stopped", otherwise a still-running service could be deleted/bounced
// prematurely.
func stopRunningService(s *mgr.Service) {
	if _, err := s.Control(svc.Stop); err != nil {
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_SERVICE_NOT_ACTIVE {
			fmt.Printf("Warning: failed to signal service stop: %v\n", err)
		}
	}
	for range serviceStopPollAttempts {
		if status, qerr := s.Query(); qerr == nil && status.State == svc.Stopped {
			return
		}
		time.Sleep(serviceStopPollInterval)
	}
}

// elevationHint returns an annotation to append to error messages
// when the underlying Windows error indicates a missing privilege.
// Service Manager operations require an Administrator-elevated
// process; the raw "Access is denied." error from the API is
// unhelpful without that context.
func elevationHint(err error) string {
	var errno windows.Errno
	if errors.As(err, &errno) && errno == windows.ERROR_ACCESS_DENIED {
		return "\nHint: run this command from an elevated (Administrator) prompt."
	}
	return ""
}

// isServiceNotExist reports whether err indicates that the service is
// not registered with the SCM (i.e. this is a fresh install). Used to
// distinguish "go create the service" from real OpenService failures.
func isServiceNotExist(err error) bool {
	var errno windows.Errno
	return errors.As(err, &errno) && errno == windows.ERROR_SERVICE_DOES_NOT_EXIST
}

// quoteServicePath wraps p in double quotes when it contains
// whitespace and is not already quoted. SCM treats BinaryPathName as
// a command line, so an unquoted "C:\Program Files\alpamon\..." can
// be parsed as "C:\Program.exe Files\alpamon\..." and execute a
// sibling file if one exists. Paths without whitespace are returned
// unchanged to keep SCM output readable.
func quoteServicePath(p string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, `"`) {
		return p
	}
	if !strings.ContainsAny(p, " \t") {
		return p
	}
	return `"` + p + `"`
}

// normalizeServiceBinaryPath rewrites the service's BinaryPathName to
// the provided binaryPathName via UpdateConfig. Used immediately after
// mgr.CreateService to undo the double-encoding caused by
// syscall.EscapeArg inside CreateService — see the call site in
// startService for the full rationale. UpdateConfig writes
// BinaryPathName verbatim (no EscapeArg), so the stored ImagePath ends
// up as the command line we constructed via quoteServicePath, wrapped
// once with a single pair of double quotes when needed.
func normalizeServiceBinaryPath(s *mgr.Service, binaryPathName string) error {
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}
	cfg.BinaryPathName = binaryPathName
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service config: %w", err)
	}
	return nil
}
