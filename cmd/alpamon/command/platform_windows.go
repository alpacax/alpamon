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
func restartAgent() {
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
