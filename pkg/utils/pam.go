package utils

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	pamQueryTimeout = 3 * time.Second
	pamCacheTTL     = 3 * time.Hour
)

var (
	pamCache      string
	pamCacheTime  time.Time
	pamCacheMutex sync.Mutex
)

// InvalidatePamCache clears the cached pam version so the next call to
// GetPamVersion will re-query the system. Call this after upgrading alpamon-pam
// to avoid reporting a stale version for up to pamCacheTTL.
func InvalidatePamCache() {
	pamCacheMutex.Lock()
	defer pamCacheMutex.Unlock()
	pamCache = ""
	pamCacheTime = time.Time{}
}

// GetPamVersion returns the installed alpamon-pam package version.
// Returns empty string if the package is not installed.
// Results are cached with a TTL to avoid spawning external processes on every sync.
func GetPamVersion() string {
	pamCacheMutex.Lock()
	defer pamCacheMutex.Unlock()

	if !pamCacheTime.IsZero() && time.Since(pamCacheTime) < pamCacheTTL {
		return pamCache
	}

	pamCache = queryPamVersion()
	pamCacheTime = time.Now()
	return pamCache
}

func queryPamVersion() string {
	if runtime.GOOS != "linux" {
		return ""
	}

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

var (
	sshdUsePAMCache     string
	sshdUsePAMCacheTime time.Time
)

// GetSSHDUsePAM reports sshd's effective UsePAM setting: "yes", "no",
// or "" when it cannot be determined (no sshd, non-linux, query error).
// A host reporting anything but "yes" bypasses PAM-based access
// detection for pubkey SSH logins, so the value is surfaced to the
// server via sync. Cached with the same TTL as the pam version to avoid
// spawning sshd -T on every sync cycle.
func GetSSHDUsePAM() string {
	pamCacheMutex.Lock()
	defer pamCacheMutex.Unlock()

	if !sshdUsePAMCacheTime.IsZero() && time.Since(sshdUsePAMCacheTime) < pamCacheTTL {
		return sshdUsePAMCache
	}

	sshdUsePAMCache = querySSHDUsePAM()
	sshdUsePAMCacheTime = time.Now()
	return sshdUsePAMCache
}

func querySSHDUsePAM() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		// sshd is typically in sbin, which may not be on PATH.
		for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
			if _, statErr := os.Stat(p); statErr == nil {
				sshdPath = p
				break
			}
		}
	}
	if sshdPath == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), pamQueryTimeout)
	defer cancel()

	// sshd -T prints the effective config; requires root, which alpamon
	// runs as in production. Errors simply yield "unknown".
	out, err := exec.CommandContext(ctx, sshdPath, "-T").Output()
	if err != nil {
		return ""
	}
	return parseSSHDUsePAM(string(out))
}

// parseSSHDUsePAM extracts the usepam value from sshd -T output.
func parseSSHDUsePAM(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 2 && fields[0] == "usepam" {
			return fields[1]
		}
	}
	return ""
}
