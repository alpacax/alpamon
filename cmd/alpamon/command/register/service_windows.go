package register

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	alpamonBinPath       = `C:\Program Files\alpamon\alpamon.exe`
	serviceName          = "alpamon"
	serviceDisplayName   = "Alpamon Agent"
	serviceDescription   = "Secure server agent for the Alpacon infrastructure access platform."
	recoveryResetSeconds = 60
	recoveryRestartDelay = 5 * time.Second
)

func ensureDirectories() error {
	return utils.EnsureDirectories()
}

func startService() error {
	binPath := alpamonBinPath
	if exe, err := os.Executable(); err == nil {
		binPath = exe
	} else {
		fmt.Printf("Warning: os.Executable() failed (%v); falling back to %s\n", err, binPath)
	}

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
			binPath,
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
