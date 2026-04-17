package register

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName          = "alpamon"
	serviceDisplayName   = "Alpamon Agent"
	serviceDescription   = "Secure server agent for the Alpacon infrastructure access platform."
	recoveryResetSeconds = 60
	recoveryRestartDelay = 5 * time.Second
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
	s, err := m.OpenService(serviceName)
	if err != nil {
		if !isServiceNotExist(err) {
			return fmt.Errorf("open service: %w%s", err, elevationHint(err))
		}
		s, err = m.CreateService(
			serviceName,
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
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: recoveryRestartDelay},
		{Type: mgr.ServiceRestart, Delay: recoveryRestartDelay},
		{Type: mgr.NoAction},
	}
	if err := s.SetRecoveryActions(recoveryActions, recoveryResetSeconds); err != nil {
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
