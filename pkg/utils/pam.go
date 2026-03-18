package utils

import (
	"context"
	"os/exec"
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
