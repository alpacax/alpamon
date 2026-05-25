package main

import (
	"os"

	"github.com/alpacax/alpamon/v2/cmd/alpamon/command"
)

func main() {
	if err := command.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
