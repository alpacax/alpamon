package command

import (
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
)

// svcName is the Windows Service name registered by `alpamon register`.
// Must match what register creates.
const svcName = "alpamon"

// runningAsWindowsService reports whether the current process was
// launched by the Windows Service Control Manager.
func runningAsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		// IsWindowsService touches the Windows API; if it fails we
		// assume interactive and let runAgent() handle things.
		return false
	}
	return isSvc
}

// runService starts alpamon under the Windows Service Control Manager.
// It maps SCM events to the existing runAgent flow by:
//   - launching runAgent in a goroutine (it manages its own lifecycle
//     via ContextManager and returns when shutdown is signalled);
//   - mirroring Stop / Shutdown / Preshutdown requests into
//     agentCtrl.stop(), which we wire to ContextManager.Shutdown via
//     a package-level hook;
//   - reporting status transitions back to SCM.
//
// SCM blocks ChangeServiceConfig2W callers on StartPending / StopPending
// transitions, so we report Running as soon as runAgent has started
// and Stopped once it returns.
func runService() {
	handler := &alpamonService{}
	// svc.Run blocks until the service stops. It returns the last
	// error it encountered, if any; log it and exit normally so SCM
	// doesn't reboot the service under a Recovery Action for a
	// clean stop.
	if err := svc.Run(svcName, handler); err != nil {
		log.Error().Err(err).Msg("Windows Service dispatcher returned an error.")
	}
}

type alpamonService struct{}

// Execute is the svc.Handler contract. It accepts SCM requests on r
// and reports service status on changes. When the goroutine running
// runAgent returns (because ctx is cancelled), Execute reports
// Stopped and exits.
func (s *alpamonService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// Let runAgent start up. When triggerShutdown() is invoked by the
	// SCM branch below, runAgent's ContextManager is cancelled and the
	// function returns, which closes agentDone.
	// ready is closed once runAgent has installed the shutdown hook.
	// We wait for it before reporting Running so SCM can't deliver a
	// Stop that we'd be unable to honor.
	agentDone := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(agentDone)
		runAgent(ready)
	}()
	<-ready

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case <-agentDone:
			changes <- svc.Status{State: svc.Stopped}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				log.Info().Msgf("Windows Service received %v; initiating shutdown.", c.Cmd)
				changes <- svc.Status{State: svc.StopPending}
				triggerShutdown()
				// Wait for runAgent to finish rather than returning
				// immediately; SCM kills the process once Execute
				// returns, cutting off in-flight graceful-shutdown.
				<-agentDone
				changes <- svc.Status{State: svc.Stopped}
				return false, 0

			default:
				log.Debug().Msgf("Unexpected Windows Service control request: %v", c.Cmd)
			}
		}
	}
}
