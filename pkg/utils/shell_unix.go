//go:build !windows

package utils

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

const validShellsFilePath = "/etc/shells"

// LoadValidShells reads /etc/shells and returns the listed login shell paths.
// Returns nil if the file cannot be read or parsed.
func LoadValidShells() []string { return loadValidShellsFrom(validShellsFilePath) }

func loadValidShellsFrom(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open /etc/shells, skipping shell validation")
		return nil
	}
	defer func() { _ = file.Close() }()

	var shells []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shells = append(shells, line)
	}
	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Msg("Error reading /etc/shells")
		return nil
	}
	return shells
}
