package utils

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const pamQueryTimeout = 3 * time.Second

// GetPamVersion returns the installed alpamon-pam package version.
// Returns empty string if the package is not installed.
func GetPamVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), pamQueryTimeout)
	defer cancel()

	// Try dpkg first (Debian/Ubuntu)
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", "alpamon-pam").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	// Try rpm (RHEL/CentOS)
	out, err = exec.CommandContext(ctx, "rpm", "-q", "--queryformat", "%{VERSION}", "alpamon-pam").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}
