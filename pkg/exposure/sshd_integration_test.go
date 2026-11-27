//go:build linux && integration

package exposure

import (
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDistroSSHDExposure(t *testing.T) {
	if os.Geteuid() != 0 {
		require.Empty(t, os.Getenv("CI"), "CI requires root in an isolated Docker container")
		t.Skip("requires root in an isolated Docker container")
	}
	if _, err := os.Stat("/.dockerenv"); errors.Is(err, os.ErrNotExist) {
		require.Empty(t, os.Getenv("CI"), "CI requires an isolated Docker container")
		t.Skip("requires an isolated Docker container")
	} else {
		require.NoError(t, err)
	}
	if os.Getenv("EXPOSURE_SSHD_INSTALL_FAILED") == "1" {
		require.Empty(t, os.Getenv("CI"), "OpenSSH installation failed in CI")
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
	if missing && os.Getenv("CI") == "" {
		t.Skip("OpenSSH server package is unavailable")
	}
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

	var expected map[string]*string
	var hasTemplate bool
	if debianFamily {
		expected = distroDerivedSettings(t)
		for _, name := range []string{"ssh@.service", "sshd@.service"} {
			_, err := os.Stat(filepath.Join("/lib/systemd/system", name))
			if err == nil {
				hasTemplate = true
			} else {
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		}
	}
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
				if hasTemplate || expected == nil {
					assert.Equal(t, expected, effective)
				} else {
					assert.Nil(t, effective, "the image has no verifiable per-connection service")
					t.Run("verified per-connection service", func(t *testing.T) {
						// Keep the image's sshd_config and drop-ins intact.
						file := "/etc/systemd/system/ssh@.service"
						f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
						require.NoError(t, err)
						t.Cleanup(func() { assert.NoError(t, os.Remove(file)) })
						_, err = f.WriteString("[Service]\nExecStart=/usr/sbin/sshd -i\n")
						require.NoError(t, err)
						require.NoError(t, f.Close())
						report := newCollector(opts).collect(t.Context())
						assert.Contains(t, report.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
						assert.Equal(t, expected, report.SSHD.Effective)
					})
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
				native := parseSSHDT(dump).effective
				assert.Equal(t, native, effective)
				if expected != nil {
					for key, want := range expected {
						switch key {
						case "pubkeyacceptedalgorithms", "casignaturealgorithms":
							// The product default spans multiple OpenSSH releases.
							if want != nil && *want == sshdDefaults[key] {
								continue
							}
						case "permitrootlogin":
							if native[key] != nil && *native[key] == "without-password" {
								native[key] = ptr("prohibit-password")
							}
						}
						assert.Equal(t, want, native[key], key)
					}
				}
			}
			assert.NotContains(t, reasons, reasonSSHDUnavailable)
		})
	}
}

// These images ship simple global directives and at most a top-level Include.
// Read the installed files independently of the collector, and fail visibly
// when an image changes to a configuration this expectation does not model.
func distroDerivedSettings(t *testing.T) map[string]*string {
	t.Helper()
	version, err := exec.CommandContext(t.Context(), "dpkg-query", "-W", "-f=${Version}", "openssh-server").Output()
	require.NoError(t, err)
	upstream := strings.SplitN(strings.SplitN(string(version), "-", 2)[0], "p", 2)[0]
	if _, after, ok := strings.Cut(upstream, ":"); ok {
		upstream = after
	}
	major, minor, ok := strings.Cut(upstream, ".")
	require.True(t, ok)
	m, err := strconv.Atoi(major)
	require.NoError(t, err)
	n, err := strconv.Atoi(minor)
	require.NoError(t, err)
	if m < 8 || m == 8 && n < 7 {
		return nil
	}
	// Only plain binary invocations are eligible. A leading systemd command
	// prefix on a packaged template is outside the collector's simple grammar.
	for _, file := range []string{"/lib/systemd/system/ssh@.service", "/lib/systemd/system/sshd@.service"} {
		content, err := os.ReadFile(file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		if strings.Contains(string(content), "ExecStart=-") {
			return nil
		}
	}
	values := maps.Clone(sshdDefaults)
	seen := map[string]bool{}
	var read func(string, bool)
	read = func(file string, main bool) {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		for line := range strings.SplitSeq(string(data), "\n") {
			directive, _, _ := strings.Cut(line, "#")
			fields := strings.Fields(directive)
			if len(fields) == 0 {
				continue
			}
			key := strings.ToLower(fields[0])
			switch key {
			case "include":
				require.True(t, main)
				for _, pattern := range fields[1:] {
					require.True(t, filepath.IsAbs(pattern))
					files, err := filepath.Glob(pattern)
					require.NoError(t, err)
					for _, f := range files {
						read(f, false)
					}
				}
			case "match":
				t.Fatalf("unexpected Match in shipped config %s", file)
			default:
				if _, tracked := values[key]; !tracked {
					continue
				}
				v := strings.Join(fields[1:], " ")
				if seen[key] {
					if multiLineKeywords[key] {
						values[key] += " " + v
					}
				} else {
					values[key] = v
					seen[key] = true
				}
			}
		}
	}
	read(sshdConfigPath, true)
	expected := map[string]*string{}
	for key, v := range values {
		if v == "" {
			expected[key] = nil
		} else {
			expected[key] = &v
		}
	}
	return expected
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
