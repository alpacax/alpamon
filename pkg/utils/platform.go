package utils

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/host"
)

// Three axes because on SUSE the reported value (PlatformLike=rhel, per SERVER_PLATFORMS) and the local command (PackageManager=zypper) disagree; PlatformID keeps the raw id for the Tumbleweed branch.
var (
	PlatformLike   string
	PackageManager string
	PlatformID     string
)

// Mirrors alpacon-server servers/constants.py PLATFORM_ALIASES 1:1 — never add ids the server lacks: write-once Server.platform makes a divergence permanent.
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

// Mirrors SUSE_PLATFORM_PREFIXES; prefix-matched because the ids proliferate (opensuse-microos, sle-micro, sle_hpc) and gopsutil's exact-match PlatformFamily returns "" for several.
var susePrefixes = []string{"opensuse", "sle", "suse"}

// Exported so the switches in pkg/executor/handlers/system are compiler-checked; PkgNone (windows self-updates) is non-empty so a zero value falls to default instead of that arm.
const (
	PkgApt    = "apt"
	PkgYum    = "yum"
	PkgZypper = "zypper"
	PkgBrew   = "brew"
	PkgNone   = "none"
)

// Pure, so the table is testable without a host; ok=false must never be defaulted by callers (see platformAliases).
func ResolvePlatform(goos, rawPlatform string) (like, pkgManager string, ok bool) {
	switch goos {
	case "darwin":
		return "darwin", PkgBrew, true
	case "windows":
		return "windows", PkgNone, true
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

// The alpacon-server SERVER_PLATFORMS set: the register endpoint gates Server.platform with a ChoiceField over exactly these.
var serverPlatforms = map[string]bool{
	"debian":  true,
	"rhel":    true,
	"darwin":  true,
	"windows": true,
}

// Rejects an explicit --platform the server would reject, so the operator fails fast instead of at the registration request.
func ValidateServerPlatform(p string) error {
	if !serverPlatforms[p] {
		return fmt.Errorf(
			"invalid --platform %q: accepted values are debian, rhel, darwin, windows", p)
	}
	return nil
}

// The value register and migrate send; errors instead of defaulting because the server persists it write-once, fixable only by re-registering.
func DetectRegistrationPlatform() (string, error) {
	var raw string
	if runtime.GOOS == "linux" {
		info, err := host.Info()
		if err != nil {
			return "", fmt.Errorf(
				"failed to detect the host platform: %w.\n"+
					"Pass --platform debian|rhel to skip detection if you know the host is compatible",
				err)
		}
		raw = info.Platform
	}
	return ResolveRegistrationPlatform(runtime.GOOS, raw)
}

// DetectRegistrationPlatform's pure half, so the mapping and its error text are testable without a host.
func ResolveRegistrationPlatform(goos, raw string) (string, error) {
	like, _, ok := ResolvePlatform(goos, raw)
	if !ok {
		return "", fmt.Errorf(
			"unrecognized Linux distribution %q.\n"+
				"alpamon supports debian- and rhel-family distributions, "+
				"including openSUSE/SLES.\n"+
				"Pass --platform debian|rhel to override if you know the host is compatible",
			raw)
	}
	return like, nil
}

// Classifies the host once at startup; unclassifiable is fatal because every handler switches on these values and guessing would misreport to the server.
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

// Lives beside susePrefixes so both SUSE id decisions normalize case alike; why the caller cares is at the call site.
func IsTumbleweed(id string) bool {
	return strings.Contains(strings.ToLower(id), "tumbleweed")
}
