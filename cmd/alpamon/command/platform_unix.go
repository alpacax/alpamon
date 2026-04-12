//go:build !windows

package command

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/rs/zerolog/log"
)

func setupSignalHandler(ctxManager *agent.ContextManager) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		ctxManager.Shutdown()
	}()
}

func restartAgent() {
	executable, err := os.Executable()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", name)
		return
	}
	err = syscall.Exec(executable, os.Args, os.Environ())
	if err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", name)
	}
}
