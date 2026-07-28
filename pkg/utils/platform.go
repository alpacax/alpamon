package utils

import (
	"os"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/host"
)

// Platform classification, split across three axes because a single value
// cannot serve both consumers on SUSE:
//
//   - PlatformLike is the alpacon-server contract value. The register
//     endpoint gates it with a ChoiceField over SERVER_PLATFORMS, so it is
//     one of debian/rhel/darwin/windows and nothing else. SUSE reports rhel:
//     the three things the server gates on (rpm, wheel, useradd) answer
//     identically for both families.
//   - PackageManager picks the local command. This is where SUSE diverges:
//     zypper, not yum.
//   - PlatformID is the raw os-release id, kept for the one place a
//     distro-level distinction is unavoidable (Tumbleweed).
var (
	PlatformLike   string
	PackageManager string
	PlatformID     string
)

// platformAliases mirrors alpacon-server servers/constants.py
// PLATFORM_ALIASES. Server.platform is write-once with no admin edit path,
// so a value the two sides disagree on corrupts feature gating permanently.
// Keep the two tables 1:1: do not add ids the server does not know.
var platformAliases = map[string]string{
	"debian":    "debian",
	"ubuntu":    "debian",
	"raspbian":  "debian",
	"rhel":      "rhel",
	"centos":    "rhel",
	"redhat":    "rhel",
	"amazon":    "rhel",
	"amzn":      "rhel",
	"fedora":    "rhel",
	"rocky":     "rhel",
	"almalinux": "rhel",
	"oracle":    "rhel",
	"ol":        "rhel",
}

// susePrefixes mirrors alpacon-server SUSE_PLATFORM_PREFIXES. SUSE matches by
// prefix rather than exact id because the os-release ids proliferate
// (opensuse-leap, opensuse-tumbleweed, opensuse-microos, sles, sled,
// sle-micro, sle_hpc, ...). gopsutil's own PlatformFamily is exact-match and
// returns "" for several of these, so it cannot be the mapping source.
var susePrefixes = []string{"opensuse", "sle", "suse"}

// Local package managers. Windows has none: it self-updates the binary
// instead of going through a package channel.
//
// Exported because PackageManager is a cross-package contract: produced here,
// consumed by the switches in pkg/executor/handlers/system. A mistyped case
// label there falls through to default and silently reports the platform as
// unsupported, so the agreement needs to be compiler-enforced.
const (
	PkgApt    = "apt"
	PkgYum    = "yum"
	PkgZypper = "zypper"
	PkgBrew   = "brew"
)

// ResolvePlatform is pure: callers pass host.Info() output so the table is
// testable without a host.
//
// ok is false for a distribution neither table knows. Callers must not
// substitute a default (see platformAliases for why).
func ResolvePlatform(goos, rawPlatform string) (like, pkgManager string, ok bool) {
	switch goos {
	case "darwin":
		return "darwin", PkgBrew, true
	case "windows":
		return "windows", "", true
	case "linux":
		// fall through
	default:
		return "", "", false
	}

	id := strings.ToLower(strings.TrimSpace(rawPlatform))
	if id == "" {
		return "", "", false
	}

	for _, prefix := range susePrefixes {
		if strings.HasPrefix(id, prefix) {
			return "rhel", PkgZypper, true
		}
	}

	switch platformAliases[id] {
	case "debian":
		return "debian", PkgApt, true
	case "rhel":
		return "rhel", PkgYum, true
	}
	return "", "", false
}

// InitPlatform classifies the host once at startup. An unclassifiable
// distribution is fatal: every downstream handler switches on these values,
// and guessing would send a wrong platform to the server (see platformAliases).
func InitPlatform() {
	var raw string
	if runtime.GOOS == "linux" {
		info, err := host.Info()
		if err != nil {
			log.Error().Err(err).Msg("Failed to retrieve platform information.")
			os.Exit(1)
		}
		raw = info.Platform
	}

	like, pkgManager, ok := ResolvePlatform(runtime.GOOS, raw)
	if !ok {
		log.Fatal().Msgf(
			"Unsupported platform: os=%s distribution=%q. "+
				"alpamon supports debian- and rhel-family Linux distributions "+
				"(including openSUSE/SLES), macOS, and Windows.",
			runtime.GOOS, raw)
	}

	PlatformLike = like
	PackageManager = pkgManager
	PlatformID = raw
}

// SetPlatformLike sets PlatformLike for tests.
func SetPlatformLike(platform string) {
	PlatformLike = platform
}

// SetPackageManager sets PackageManager for tests.
func SetPackageManager(pm string) {
	PackageManager = pm
}

// SetPlatformID sets PlatformID for tests.
func SetPlatformID(id string) {
	PlatformID = id
}

// IsTumbleweed lives beside susePrefixes so both SUSE id decisions normalize
// case the same way. Why the caller cares is documented at the call site.
func IsTumbleweed(id string) bool {
	return strings.Contains(strings.ToLower(id), "tumbleweed")
}
