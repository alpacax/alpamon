package utils

import (
	"strings"
	"testing"
)

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
			if ok {
				t.Fatalf("ResolvePlatform(linux, %q) = (%q, %q, ok), want not ok", raw, like, pkgMgr)
			}
			if like != "" || pkgMgr != "" {
				t.Errorf("unsupported input must return empty values, got (%q, %q)", like, pkgMgr)
			}
		})
	}
}

// Asserted once here because register and migrate both send this value.
func TestResolveRegistrationPlatform_SuseMapsToRhel(t *testing.T) {
	got, err := ResolveRegistrationPlatform("linux", "opensuse-leap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "rhel" {
		t.Errorf("platform = %q, want rhel", got)
	}
}

// A silent "debian" default is unrecoverable: the server persists it write-once with no admin edit path.
func TestResolveRegistrationPlatform_UnsupportedReturnsError(t *testing.T) {
	_, err := ResolveRegistrationPlatform("linux", "arch")
	if err == nil {
		t.Fatal("expected an error for an unclassifiable distribution")
	}
	if !strings.Contains(err.Error(), "arch") {
		t.Errorf("error must name the distribution, got %q", err)
	}
	if !strings.Contains(err.Error(), "--platform") {
		t.Errorf("error must tell the operator about the override, got %q", err)
	}
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
			if got := IsTumbleweed(tt.id); got != tt.want {
				t.Errorf("IsTumbleweed(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
