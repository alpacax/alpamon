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
	if !strings.Contains(string(unit), want) {
		t.Errorf("configs/alpamon.service must contain %q", want)
	}
}
