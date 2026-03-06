package utils

import (
	"os/exec"
	"strings"
)

// GetPamVersion returns the installed alpamon-pam package version.
// Returns empty string if the package is not installed.
func GetPamVersion() string {
	// Try dpkg first (Debian/Ubuntu)
	out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "alpamon-pam").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	// Try rpm (RHEL/CentOS)
	out, err = exec.Command("rpm", "-q", "--queryformat", "%{VERSION}", "alpamon-pam").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}
