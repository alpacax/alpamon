package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The callers turn this into os.Exit / a return code, neither reachable from a test, so the mapping itself is what gets pinned.
func TestStartupExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"wrapped sentinel", fmt.Errorf("%w: os=linux distribution=%q", ErrUnsupportedPlatform, "gentoo"), ConfigErrorExitCode},
		{"host lookup failure", fmt.Errorf("failed to retrieve platform information: %w", errors.New("no os-release")), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, StartupExitCode(tt.err), "StartupExitCode(%v)", tt.err)
		})
	}
}

// systemd parses RestartPreventExitStatus as a literal and cannot read the Go constant, so drift between the two silently restores the restart loop this code exists to stop.
func TestConfigErrorExitCodeMatchesUnitFile(t *testing.T) {
	unit, err := os.ReadFile("../../configs/alpamon.service")
	require.NoError(t, err, "failed to read the unit file")
	want := fmt.Sprintf("RestartPreventExitStatus=%d", ConfigErrorExitCode)
	// A commented-out or misplaced directive is inert to systemd, so a substring match would pass on a unit that still restart-loops.
	var section string
	found := false
	for line := range strings.SplitSeq(string(unit), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		if section == "[Service]" && line == want {
			found = true
			break
		}
	}
	assert.True(t, found, "configs/alpamon.service must set %q under [Service]", want)
}
