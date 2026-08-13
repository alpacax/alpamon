package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
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
			if got := StartupExitCode(tt.err); got != tt.want {
				t.Errorf("StartupExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

// systemd parses RestartPreventExitStatus as a literal and cannot read the Go constant, so drift between the two silently restores the restart loop this code exists to stop.
func TestConfigErrorExitCodeMatchesUnitFile(t *testing.T) {
	unit, err := os.ReadFile("../../configs/alpamon.service")
	if err != nil {
		t.Fatalf("failed to read the unit file: %v", err)
	}
	want := fmt.Sprintf("RestartPreventExitStatus=%d", ConfigErrorExitCode)
	// A commented-out or misplaced directive is inert to systemd, so a substring match would pass on a unit that still restart-loops.
	var section string
	for line := range strings.SplitSeq(string(unit), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		if section == "[Service]" && line == want {
			return
		}
	}
	t.Errorf("configs/alpamon.service must set %q under [Service]", want)
}
