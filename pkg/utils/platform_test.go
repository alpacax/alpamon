package utils

import (
	"os"
	"runtime"
	"testing"

	"github.com/shirou/gopsutil/v4/host"
)

// Vectors deliberately mirror alpacon-server servers/test_utils.py:68-96. The
// 1:1 correspondence between the two tables is the contract, and Server.platform
// is write-once, so a divergence breaks feature gating permanently.
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

		// suse family: every row matches by prefix, not by exact id
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
		{"windows", "windows", "Microsoft Windows Server 2025 Datacenter", "windows", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			like, pkgMgr, ok := ResolvePlatform(tt.goos, tt.raw)
			if !ok {
				t.Fatalf("ResolvePlatform(%q, %q) = not ok, want ok", tt.goos, tt.raw)
			}
			if like != tt.wantLike {
				t.Errorf("platformLike = %q, want %q", like, tt.wantLike)
			}
			if pkgMgr != tt.wantPkgMgr {
				t.Errorf("packageManager = %q, want %q", pkgMgr, tt.wantPkgMgr)
			}
		})
	}
}

// alpamon must not accept an id the alpacon-server table rejects. Accepting a
// wider set splits the two tables, and the value pinned at registration cannot
// be taken back.
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
			if ok {
				t.Fatalf("ResolvePlatform(linux, %q) = (%q, %q, ok), want not ok", raw, like, pkgMgr)
			}
			if like != "" || pkgMgr != "" {
				t.Errorf("unsupported input must return empty values, got (%q, %q)", like, pkgMgr)
			}
		})
	}
}

// TestResolvePlatform_CIHost feeds ResolvePlatform the same input
// InitPlatform reads (host.Info() on linux), so every CI matrix row verifies
// that its own distro classifies. The vectors above cannot catch the #348
// class of bug: a distro present in CI but absent from the tables. Gated on
// CI so a contributor on an unsupported distro keeps a green local run.
func TestResolvePlatform_CIHost(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("CI-matrix guard: host distros are only pinned supported on CI runners")
	}

	var raw string
	if runtime.GOOS == "linux" {
		info, err := host.Info()
		if err != nil {
			t.Fatalf("host.Info() failed: %v", err)
		}
		raw = info.Platform
	}

	like, pkgManager, ok := ResolvePlatform(runtime.GOOS, raw)
	if !ok {
		t.Fatalf("CI host not classified: os=%s distribution=%q", runtime.GOOS, raw)
	}
	t.Logf("os=%s distribution=%q -> like=%s pkgManager=%s", runtime.GOOS, raw, like, pkgManager)
}

// Lock both directions: a false negative skips a needed dup, a false positive
// runs a destructive one.
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
			if got := IsTumbleweed(tt.id); got != tt.want {
				t.Errorf("IsTumbleweed(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
