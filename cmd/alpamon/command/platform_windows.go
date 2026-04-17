package command

import (
	"os"
	"os/exec"
	"os/signal"

	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/rs/zerolog/log"
)

func setupSignalHandler(ctxManager *agent.ContextManager) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		ctxManager.Shutdown()
	}()
}

// restartAgent on Windows spawns a new process and exits.
// Windows does not support syscall.Exec (process replacement).
//
// When running under the Service Control Manager, we instead rely on
// SCM's Recovery Actions to relaunch alpamon. Spawning a child while
// the SCM thinks we're a running service would fight the service's
// lifecycle; exiting with a non-zero status lets SCM notice the
// "failure" and restart us with the newly-installed binary.
func restartAgent() {
	if runningAsWindowsService() {
		log.Warn().Msgf(
			"%s is exiting with status 1 so SCM Recovery Actions restart it with the newly-installed binary. "+
				"If Recovery Actions are not configured the service will remain stopped; "+
				"re-run 'alpamon register' to apply the recommended configuration.", name,
		)
		os.Exit(1)
	}
	executable, err := os.Executable()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", name)
		return
	}
	cmd := exec.Command(executable, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", name)
		return
	}
	os.Exit(0)
}
