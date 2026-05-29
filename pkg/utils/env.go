package utils

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

// LoadEtcEnvironment parses /etc/environment and merges system-wide
// environment variables into the provided map. This supplements the PAM
// pam_env module, which is not invoked for non-login execution paths such as
// Websh PTY sessions and demoted exec/shell commands. The path is resolved via
// EnvironmentFilePath and is empty (a no-op) on platforms without an
// /etc/environment equivalent.
func LoadEtcEnvironment(env map[string]string) {
	envFilePath := EnvironmentFilePath()
	if envFilePath == "" {
		return
	}

	file, err := os.Open(envFilePath)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		env[key] = value
	}

	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Msgf("Error reading %s", envFilePath)
	}
}
