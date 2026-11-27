//go:build linux && integration

package exposure

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDistroSSHDExposure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated Docker container")
	}
	if _, err := os.Stat("/.dockerenv"); errors.Is(err, os.ErrNotExist) {
		t.Skip("requires an isolated Docker container")
	} else {
		require.NoError(t, err)
	}
	if os.Getenv("EXPOSURE_SSHD_INSTALL_FAILED") == "1" {
		t.Skip("the distro package manager could not install the OpenSSH server")
	}
	osRelease, err := os.ReadFile("/etc/os-release")
	require.NoError(t, err)
	var id string
	for line := range strings.SplitSeq(string(osRelease), "\n") {
		if value, ok := strings.CutPrefix(line, "ID="); ok {
			id = strings.Trim(value, `"'`)
			break
		}
	}
	var debianFamily bool
	switch id {
	case "debian", "ubuntu":
		debianFamily = true
	case "rocky", "rhel", "almalinux", "ol", "fedora", "amzn", "opensuse-leap":
	default:
		t.Fatalf("no sshd expectation for distro ID %q", id)
	}
	opts := defaultOptions()
	bin, missing := findSSHD(opts.root, opts.mapOwner)
	require.False(t, missing, "OpenSSH server package must provide an sshd candidate")
	require.NotEmpty(t, bin, "installed sshd must pass the collector's binary checks")

	// Generate disposable keys so even a pre-existing orphan .pub file is preserved.
	moveSSHDPathsAside(t, distroHostKeys(t)...)
	t.Cleanup(func() {
		for _, key := range distroHostKeys(t) {
			assert.NoError(t, os.Remove(key))
		}
	})
	require.NoError(t, exec.CommandContext(t.Context(), "ssh-keygen", "-A").Run())
	require.NotEmpty(t, distroHostKeys(t))

	// Ubuntu socket activation cannot be reproduced in a container. Reproduce its
	// observable state directly by collecting while /run/sshd is absent.
	for _, tc := range []struct {
		name      string
		directory bool
		noKeys    bool
	}{
		{name: "runtime directory absent"},
		{name: "runtime directory present", directory: true},
		{name: "host keys absent", directory: true, noKeys: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			moveSSHDPathsAside(t, privsepPath)
			if tc.directory {
				require.NoError(t, os.Mkdir(privsepPath, 0o755))
				t.Cleanup(func() { assert.NoError(t, os.Remove(privsepPath)) })
			}
			if tc.noKeys {
				moveSSHDPathsAside(t, distroHostKeys(t)...)
			}
			report := newCollector(opts).collect(t.Context())
			reasons := report.Categories[catSSHD].Reasons
			effective := report.SSHD.Effective
			switch {
			case tc.noKeys:
				assert.Contains(t, reasons, reasonSSHDNoHostKeys)
				assert.NotContains(t, reasons, reasonSSHDPrivsepMissing)
				assert.Nil(t, effective)
			case debianFamily && !tc.directory:
				assert.Contains(t, reasons, reasonSSHDPrivsepMissing)
				require.Len(t, effective, len(sshdDefaults))
				for key, fallback := range sshdDefaults {
					require.Contains(t, effective, key)
					if fallback != "" { // Unset access lists are null on the wire.
						assert.NotNil(t, effective[key], key)
					}
				}
			default:
				assert.NotContains(t, reasons, reasonSSHDPrivsepMissing)
				assert.NotContains(t, reasons, reasonSSHDNoHostKeys)
				assert.NotContains(t, reasons, reasonSSHDBinaryRejected)
				assert.NotContains(t, reasons, reasonSSHDTimeout)
				require.NotNil(t, effective)
				cmd := exec.CommandContext(t.Context(), bin, "-T")
				cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
				cmd.Dir = "/"
				dump, err := cmd.Output()
				require.NoError(t, err)
				defer clear(dump)
				assert.Equal(t, parseSSHDT(dump).effective, effective)
			}
			assert.NotContains(t, reasons, reasonSSHDUnavailable)
		})
	}
}

func distroHostKeys(t *testing.T) []string {
	t.Helper()
	keys, err := filepath.Glob("/etc/ssh/ssh_host_*_key")
	require.NoError(t, err)
	public, err := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	require.NoError(t, err)
	return append(keys, public...)
}

// Keep backups on the original filesystem, including when /run is a tmpfs.
func moveSSHDPathsAside(t *testing.T, paths ...string) {
	t.Helper()
	if len(paths) == 0 {
		return
	}
	dir, err := os.MkdirTemp(filepath.Dir(paths[0]), ".sshd-test-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.Remove(dir)) })
	for _, path := range paths {
		saved := filepath.Join(dir, filepath.Base(path))
		err := os.Rename(path, saved)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, os.Rename(saved, path)) })
	}
}
