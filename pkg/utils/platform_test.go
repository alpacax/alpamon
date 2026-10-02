package utils

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// applyPlatform writes package globals, so restore them and keep test ordering from leaking.
func savePlatformGlobals(t *testing.T) {
	t.Helper()
	like, pkgManager, id := PlatformLike, PackageManager, PlatformID
	t.Cleanup(func() {
		PlatformLike, PackageManager, PlatformID = like, pkgManager, id
	})
}

// Vectors mirror alpacon-server servers/test_utils.py:68-96: the 1:1 table correspondence is the contract, and write-once Server.platform makes a divergence permanent.
func TestResolvePlatform(t *testing.T) {
	tests := []struct {
		name       string
		goos       string
		raw        string
		wantLike   string
		wantPkgMgr string
	}{
		{"debian", "linux", "debian", "debian", "apt"},
		{"ubuntu", "linux", "ubuntu", "debian", "apt"},
		{"raspbian", "linux", "raspbian", "debian", "apt"},

		{"rhel", "linux", "rhel", "rhel", "yum"},
		{"centos", "linux", "centos", "rhel", "yum"},
		{"redhat", "linux", "redhat", "rhel", "yum"},
		{"amazon", "linux", "amazon", "rhel", "yum"},
		{"amzn", "linux", "amzn", "rhel", "yum"},
		{"fedora", "linux", "fedora", "rhel", "yum"},
		{"rocky", "linux", "rocky", "rhel", "yum"},
		{"almalinux", "linux", "almalinux", "rhel", "yum"},
		{"oracle", "linux", "oracle", "rhel", "yum"},
		{"ol", "linux", "ol", "rhel", "yum"},

		// Prefix-matched; the immutable variants (opensuse-microos, sle-micro) pin table parity only, not support: their read-only root likely breaks the zypper commands.
		{"suse", "linux", "suse", "rhel", "zypper"},
		{"opensuse", "linux", "opensuse", "rhel", "zypper"},
		{"opensuse-leap", "linux", "opensuse-leap", "rhel", "zypper"},
		{"opensuse-tumbleweed", "linux", "opensuse-tumbleweed", "rhel", "zypper"},
		{"opensuse-microos", "linux", "opensuse-microos", "rhel", "zypper"},
		{"sles", "linux", "sles", "rhel", "zypper"},
		{"sled", "linux", "sled", "rhel", "zypper"},
		{"sle-micro", "linux", "sle-micro", "rhel", "zypper"},
		{"sle_hpc", "linux", "sle_hpc", "rhel", "zypper"},

		{"uppercase", "linux", "SLES", "rhel", "zypper"},
		{"padded", "linux", "  sles ", "rhel", "zypper"},

		// non-linux: raw platform is ignored
		{"darwin", "darwin", "darwin", "darwin", "brew"},
		{"windows", "windows", "Microsoft Windows Server 2025 Datacenter", "windows", "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			like, pkgMgr, ok := ResolvePlatform(tt.goos, tt.raw)
			require.True(t, ok, "ResolvePlatform(%q, %q) = not ok, want ok", tt.goos, tt.raw)
			assert.Equal(t, tt.wantLike, like, "platformLike")
			assert.Equal(t, tt.wantPkgMgr, pkgMgr, "packageManager")
		})
	}
}

// A wider set than the server's splits the two tables, and the value pinned at registration cannot be taken back.
func TestResolvePlatform_Unsupported(t *testing.T) {
	for _, raw := range []string{
		"arch", "alpine", "gentoo",
		// slackware also guards against the "sle" prefix overmatching.
		"slackware",
		"linuxmint", "cloudlinux", "uos",
		"", "   ",
	} {
		t.Run(raw, func(t *testing.T) {
			like, pkgMgr, ok := ResolvePlatform("linux", raw)
			require.False(t, ok, "ResolvePlatform(linux, %q) = (%q, %q, ok), want not ok", raw, like, pkgMgr)
			assert.Empty(t, like, "unsupported input must return empty values")
			assert.Empty(t, pkgMgr, "unsupported input must return empty values")
		})
	}
}

// Asserted once here because register and migrate both send this value.
func TestResolveRegistrationPlatform_SuseMapsToRhel(t *testing.T) {
	got, err := ResolveRegistrationPlatform("linux", "opensuse-leap")
	require.NoError(t, err)
	assert.Equal(t, "rhel", got, "platform")
}

// A silent "debian" default is unrecoverable: the server persists it write-once with no admin edit path.
func TestResolveRegistrationPlatform_UnsupportedReturnsError(t *testing.T) {
	_, err := ResolveRegistrationPlatform("linux", "arch")
	require.Error(t, err, "expected an error for an unclassifiable distribution")
	assert.ErrorContains(t, err, "arch", "error must name the distribution")
	assert.ErrorContains(t, err, "--platform", "error must tell the operator about the override")
}

// --platform forwards verbatim to write-once Server.platform: all four values are server-side members, but "windows" on Linux would poison the record.
func TestValidateServerPlatform(t *testing.T) {
	for _, tt := range []struct {
		goos, p string
		ok      bool
	}{
		{"linux", "debian", true},
		{"linux", "rhel", true},
		{"darwin", "darwin", true},
		{"windows", "windows", true},

		{"linux", "windows", false},
		{"linux", "darwin", false},
		{"linux", "rehl", false},
		{"darwin", "debian", false},
		{"windows", "rhel", false},
	} {
		t.Run(tt.goos+"/"+tt.p, func(t *testing.T) {
			err := ValidateServerPlatform(tt.goos, tt.p)
			if tt.ok {
				require.NoError(t, err, "ValidateServerPlatform(%q, %q)", tt.goos, tt.p)
			} else {
				require.Error(t, err, "expected an error for a value invalid on this host")
				assert.ErrorContains(t, err, tt.p, "error must name the rejected value")
			}
		})
	}
}

// Runs the real startup path instead of re-reading the host itself, so every CI row guards its own distro — the #348 case the pure vectors miss; CI-gated to keep local runs green off-matrix.
func TestInitPlatform_CIHost(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("CI-matrix guard: host distros are only pinned supported on CI runners")
	}
	savePlatformGlobals(t)

	require.NoError(t, InitPlatform(), "CI host not classified")
	t.Logf("os=%s -> like=%s pkgManager=%s id=%q", runtime.GOOS, PlatformLike, PackageManager, PlatformID)
}

// Both directions: a false negative skips a needed dup, a false positive runs a destructive one.
func TestIsTumbleweed(t *testing.T) {
	for _, tt := range []struct {
		id   string
		want bool
	}{
		{"opensuse-tumbleweed", true},
		{"opensuse-tumbleweed-kubic", true},
		{"openSUSE-Tumbleweed", true},
		{"opensuse-leap", false},
		{"sles", false},
		{"sle-micro", false},
		{"rhel", false},
		{"", false},
	} {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.want, IsTumbleweed(tt.id), "IsTumbleweed(%q)", tt.id)
		})
	}
}

// ValidateServerPlatform accepts debian on any Linux host, so a contradicting
// override is the only signal left that the write-once record is about to
// disagree with the package manager the agent runs.
func TestResolveServerPlatform(t *testing.T) {
	detects := func(p string) func() (string, error) {
		return func() (string, error) { return p, nil }
	}
	fails := func() (string, error) { return "", errors.New("unrecognized Linux distribution \"arch\"") }

	tests := []struct {
		name        string
		explicit    string
		detect      func() (string, error)
		want        string
		wantWarning string
		wantErr     string
	}{
		{name: "detection fills an omitted platform", detect: detects("rhel"), want: "rhel"},
		{name: "detection failure propagates", detect: fails, wantErr: "arch"},
		{name: "override agreeing with detection is silent", explicit: "rhel", detect: detects("rhel"), want: "rhel"},
		{
			name: "override contradicting detection warns", explicit: "debian", detect: detects("rhel"),
			want: "debian", wantWarning: "rhel",
		},
		{
			// A failed detection is why --platform exists, so it must not warn.
			name: "override is silent when detection fails", explicit: "debian", detect: fails, want: "debian",
		},
		{name: "cross-os override is rejected", explicit: "windows", detect: detects("rhel"), wantErr: "invalid --platform"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warning, err := ResolveServerPlatform("linux", tt.explicit, tt.detect)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "platform")
			if tt.wantWarning == "" {
				assert.Empty(t, warning, "expected no warning")
			} else {
				assert.Contains(t, warning, tt.wantWarning, "warning must name the detected platform")
			}
		})
	}
}

// Callers pick ConfigErrorExitCode off this sentinel, so an unwrapped error would silently downgrade the failure back to a restartable exit 1.
func TestApplyPlatform_UnsupportedWrapsSentinel(t *testing.T) {
	savePlatformGlobals(t)
	SetPlatformLike("untouched")
	SetPackageManager("untouched")
	SetPlatformID("untouched")

	err := applyPlatform("linux", "gentoo")
	require.ErrorIs(t, err, ErrUnsupportedPlatform, "error must wrap ErrUnsupportedPlatform")
	assert.ErrorContains(t, err, "gentoo", "error must name the distribution")
	assert.Equal(t, "untouched", PlatformLike, "a failed classification must leave the globals alone")
	assert.Equal(t, "untouched", PackageManager, "a failed classification must leave the globals alone")
	assert.Equal(t, "untouched", PlatformID, "a failed classification must leave the globals alone")
}

// The three globals disagree on SUSE, so each has to land from its own source rather than be derived from another.
func TestApplyPlatform_SetsGlobals(t *testing.T) {
	savePlatformGlobals(t)

	for _, tt := range []struct {
		goos, raw, like, pkgManager, id string
	}{
		{"linux", "ubuntu", "debian", PkgApt, "ubuntu"},
		{"linux", "rocky", "rhel", PkgYum, "rocky"},
		{"linux", "opensuse-tumbleweed", "rhel", PkgZypper, "opensuse-tumbleweed"},
		{"darwin", "", "darwin", PkgBrew, ""},
		{"windows", "", "windows", PkgNone, ""},
	} {
		t.Run(tt.goos+"/"+tt.raw, func(t *testing.T) {
			require.NoError(t, applyPlatform(tt.goos, tt.raw), "applyPlatform(%q, %q)", tt.goos, tt.raw)
			assert.Equal(t, tt.like, PlatformLike, "PlatformLike")
			assert.Equal(t, tt.pkgManager, PackageManager, "PackageManager")
			assert.Equal(t, tt.id, PlatformID, "PlatformID")
		})
	}
}
