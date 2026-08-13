package utils

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

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
