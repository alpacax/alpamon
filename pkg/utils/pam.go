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
// to avoid reporting a stale version for up to pamCacheTTL. The sshd UsePAM
// cache is deliberately independent (see GetSSHDUsePAM) and is not touched
// here: a pam-package upgrade does not change sshd's configuration.
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

// The sshd UsePAM check keeps its own cache and mutex, independent of the
// pam-version cache. The two are unrelated (a pam-package upgrade does not
// change sshd's config), so InvalidatePamCache must not touch this, and
// running sshd -T here must not block a concurrent GetPamVersion caller.
var (
	sshdUsePAMCache     string
	sshdUsePAMCacheTime time.Time
	sshdUsePAMMutex     sync.Mutex
)

// GetSSHDUsePAM reports sshd's UsePAM setting as configured on disk:
// "yes", "no", or nil when it cannot be determined (no sshd, non-linux,
// query error). A host reporting anything but "yes" bypasses PAM-based
// access detection for pubkey SSH logins, so the value is surfaced to
// the server via sync. Cached with the same TTL as the pam version to
// avoid spawning sshd -T on every sync cycle.
//
// It returns a pointer so that "undeterminable" reaches the server as an
// explicit JSON null instead of an omitted key: the server preserves the
// previous value for an absent key, which would keep a host that has lost
// sshd reporting its last known value forever.
//
// The value is what sshd -T reads from the config files, not what the
// running daemon loaded. An operator who edits UsePAM without reloading
// sshd gets the on-disk answer, which may not match the live daemon.
func GetSSHDUsePAM() *string {
	sshdUsePAMMutex.Lock()
	defer sshdUsePAMMutex.Unlock()

	if sshdUsePAMCacheTime.IsZero() || time.Since(sshdUsePAMCacheTime) >= pamCacheTTL {
		sshdUsePAMCache = querySSHDUsePAM()
		sshdUsePAMCacheTime = time.Now()
	}

	if sshdUsePAMCache == "" {
		return nil
	}
	// Copy so callers can never mutate the cached value through the pointer.
	value := sshdUsePAMCache
	return &value
}

func querySSHDUsePAM() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	sshdPath := lookupSSHDPath()
	if sshdPath == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), pamQueryTimeout)
	defer cancel()

	// sshd -T prints the effective config; requires root, which alpamon
	// runs as in production. Errors simply yield "" (undeterminable).
	out, err := exec.CommandContext(ctx, sshdPath, "-T").Output()
	if err != nil {
		return ""
	}
	return parseSSHDUsePAM(string(out))
}

// lookupSSHDPath returns the sshd binary to exec, or "" when none is found.
// The canonical sbin locations are tried first so PATH plays no part in what
// alpamon runs as root, and LookPath is only a fallback whose result is
// discarded on any error: since Go 1.19 it returns a non-empty *relative*
// path together with exec.ErrDot when the match resolved through a "." (or
// empty) entry in PATH.
func lookupSSHDPath() string {
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		return ""
	}
	return sshdPath
}

// parseSSHDUsePAM extracts the usepam value from sshd -T output. Anything
// other than yes/no is reported as undeterminable rather than forwarded:
// the value rides the same sync PATCH as version, pam_version and load, so
// an unexpected token would make DRF reject all of them, not just this field.
func parseSSHDUsePAM(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 2 && fields[0] == "usepam" {
			if fields[1] == "yes" || fields[1] == "no" {
				return fields[1]
			}
			return ""
		}
	}
	return ""
}
