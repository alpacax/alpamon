//go:build linux

package exposure

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type execRecord struct {
	name string
	args []string
}

// recordExec replaces commandContext for the test and records every command
// the package would start.
func recordExec(t *testing.T) func() []execRecord {
	t.Helper()
	var mu sync.Mutex
	var got []execRecord
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		got = append(got, execRecord{name: name, args: args})
		mu.Unlock()
		return exec.CommandContext(ctx, name, args...)
	}
	t.Cleanup(func() { commandContext = exec.CommandContext })
	return func() []execRecord {
		mu.Lock()
		defer mu.Unlock()
		return append([]execRecord(nil), got...)
	}
}

// fakeSSHD installs a stand-in sshd script under root at /usr/sbin/sshd.
func fakeSSHD(t *testing.T, root, script string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr/sbin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr/sbin/sshd"), []byte("#!/bin/sh\n"+script), 0o755))
}

func rootOwned(string, uint32) uint32 { return 0 }

func TestRunSSHDTRunsOnlySSHDDashT(t *testing.T) {
	root := t.TempDir()
	fakeSSHD(t, root, "echo passwordauthentication no\necho usepam yes\n")
	calls := recordExec(t)
	run := runSSHDT(context.Background(), root, rootOwned)
	require.True(t, run.ok)
	assert.Equal(t, "no", *parseSSHDT(run.out).effective["passwordauthentication"])
	assert.Equal(t, []execRecord{{name: filepath.Join(root, "/usr/sbin/sshd"), args: []string{"-T"}}}, calls())
}

func TestRunSSHDTMissingAndForeignBinary(t *testing.T) {
	root := t.TempDir()
	calls := recordExec(t)
	assert.Equal(t, sshdRun{notInstalled: true}, runSSHDT(context.Background(), root, rootOwned))

	fakeSSHD(t, root, "echo usepam yes\n")
	notRoot := func(string, uint32) uint32 { return 1000 }
	assert.Equal(t, sshdRun{reason: reasonSSHDBinaryRejected}, runSSHDT(context.Background(), root, notRoot), "a binary not owned by root is never run")
	assert.Empty(t, calls())

	require.NoError(t, os.Remove(filepath.Join(root, "usr/sbin/sshd")))
	require.NoError(t, os.Symlink("/bin/true", filepath.Join(root, "usr/sbin/sshd")))
	assert.False(t, runSSHDT(context.Background(), root, rootOwned).ok, "a symlinked binary is never run")
	assert.Empty(t, calls())
}

func TestRunSSHDTRejectsWritableBinaryAndParent(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		mode os.FileMode
		uid  uint32
	}{
		{"group-writable binary", "usr/sbin/sshd", 0o775, 0},
		{"world-writable binary", "usr/sbin/sshd", 0o757, 0},
		{"group-writable parent", "usr/sbin", 0o775, 0},
		{"world-writable parent", "usr/sbin", 0o777, 0},
		{"non-root parent", "usr/sbin", 0o755, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fakeSSHD(t, root, "echo usepam yes\n")
			require.NoError(t, os.Chmod(filepath.Join(root, tc.path), tc.mode))
			calls := recordExec(t)
			mapOwner := func(p string, _ uint32) uint32 {
				if p == "/"+tc.path {
					return tc.uid
				}
				return 0
			}
			assert.Equal(t, sshdRun{reason: reasonSSHDBinaryRejected}, runSSHDT(context.Background(), root, mapOwner))
			assert.Empty(t, calls())
		})
	}
}

func TestRunSSHDTFailureAndCap(t *testing.T) {
	root := t.TempDir()
	fakeSSHD(t, root, "echo usepam yes\nexit 1\n")
	assert.False(t, runSSHDT(context.Background(), root, rootOwned).ok)

	fakeSSHD(t, root, "yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | head -c 300000\n")
	assert.False(t, runSSHDT(context.Background(), root, rootOwned).ok, "stdout over the cap is a failure")
}

func TestRunSSHDTTimeoutKillsAndReaps(t *testing.T) {
	root := t.TempDir()
	fakeSSHD(t, root, "exec sleep 60\n")
	start := time.Now()
	run := runSSHDT(context.Background(), root, rootOwned)
	assert.Equal(t, sshdRun{reason: reasonSSHDTimeout}, run)
	assert.Less(t, time.Since(start), sshdTimeout+3*time.Second)
}

// Fake sudo, visudo, cvtsudoers and sudo-rs first on PATH each leave a
// marker when run. A full read over the sudo fixture must leave none, and
// the only command started is sshd -T.
func TestCollectRunsNoSudoTooling(t *testing.T) {
	bin := t.TempDir()
	markers := t.TempDir()
	for _, name := range []string{"sudo", "visudo", "cvtsudoers", "sudo-rs", "sudoedit"} {
		script := "#!/bin/sh\ntouch " + filepath.Join(markers, name) + "\n"
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755))
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	dir := filepath.Join(fixturesDir, "hosts", "sudo-groups")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	fakeSSHD(t, root, "cat "+filepath.Join(dir, "sshd-T.txt")+"\n")
	calls := recordExec(t)
	opts := caseOptions(t, dir, spec, root, proc)
	opts.runSSHD = func(ctx context.Context) sshdRun { return runSSHDT(ctx, root, rootOwned) }
	r := newCollector(opts).collect(context.Background())
	require.NotEmpty(t, r.Accounts)

	entries, err := os.ReadDir(markers)
	require.NoError(t, err)
	assert.Empty(t, entries, "a sudo tool was run")
	for _, c := range calls() {
		assert.Equal(t, []string{"-T"}, c.args)
		assert.True(t, strings.HasSuffix(c.name, "/usr/sbin/sshd"))
	}
	assert.Len(t, calls(), 1)
}

func TestFailedSSHDProbeLeavesHostUntouched(t *testing.T) {
	for _, tc := range []struct {
		name, script, reason string
		wantEffective        bool
	}{
		{"missing directory", "echo '" + privsepDiagnostic + "' >&2; exit 1", reasonSSHDPrivsepMissing, true},
		{"no host keys", "echo 'sshd: no hostkeys available -- exiting.' >&2; exit 1", reasonSSHDNoHostKeys, false},
		{"long diagnostic", "echo LEAKCANARY >&2; head -c 5000 /dev/zero >&2; exit 1", reasonSSHDUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			fakeSSHD(t, root, tc.script)
			calls := recordExec(t)
			logs := captureLogs(t)
			testHookOpenFlags = func(_ string, flags int) {
				assert.Zero(t, flags&(unix.O_ACCMODE|unix.O_CREAT|unix.O_TRUNC|unix.O_APPEND))
			}
			t.Cleanup(func() { testHookOpenFlags = nil })
			opts := caseOptions(t, dir, spec, root, proc)
			opts.runSSHD = func(ctx context.Context) sshdRun { return runSSHDT(ctx, root, rootOwned) }
			report := newCollector(opts).collect(t.Context())
			body, err := finalize(report)
			require.NoError(t, err)
			assert.Contains(t, report.Categories[catSSHD].Reasons, tc.reason)
			assert.Equal(t, tc.wantEffective, report.SSHD.Effective != nil)
			assert.Len(t, calls(), 1)
			for _, canary := range []string{privsepDiagnostic, "LEAKCANARY"} {
				assert.NotContains(t, string(body), canary)
				assert.NotContains(t, logs.String(), canary)
			}
			_, err = os.Lstat(filepath.Join(root, privsepPath))
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

// Only sshd_linux.go may start a process, and only through commandContext.
func TestOnlySSHDStartsAProcess(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, err)
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "os/exec" {
				assert.Equal(t, "sshd_linux.go", f, "only the sshd runner may import os/exec")
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Mount", "Mkdir", "MkdirAll", "Mkdirat", "WriteFile":
				assert.Failf(t, "host mutation", "%s calls %s", f, sel.Sel.Name)
			case "StartProcess", "ForkExec", "Exec", "Command", "CommandContext":
				if f != "sshd_linux.go" {
					assert.Failf(t, "unexpected process call", "%s calls %s", f, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

func TestRunSSHDTFailureDiagnostics(t *testing.T) {
	const diagnostic = "echo '" + privsepDiagnostic + "' >&2\n"
	const noKeys = "echo 'sshd: no hostkeys available -- exiting.' >&2\n"
	for _, tc := range []struct {
		name, script, entry, reason string
	}{
		{"absent", diagnostic + "exit 1", "", reasonSSHDPrivsepMissing},
		{"present directory", diagnostic + "exit 1", "directory", ""},
		{"present file", diagnostic + "exit 1", "file", ""},
		{"no host keys", noKeys + "exit 1", "", reasonSSHDNoHostKeys},
		{"fatal prefix", "echo 'fatal: no hostkeys available -- exiting.' >&2; exit 1", "", reasonSSHDNoHostKeys},
		{"both diagnostics with directory absent", noKeys + diagnostic + "exit 1", "", ""},
		{"both diagnostics with directory present", diagnostic + noKeys + "exit 1", "directory", reasonSSHDNoHostKeys},
		{"no keys followed by signal", noKeys + "kill -TERM $$", "", ""},
		{"no keys followed by overflow", noKeys + "head -c 5000 /dev/zero >&2; exit 1", "", ""},
		{"another fatal", "echo 'fatal: configuration error' >&2\n" + diagnostic + "exit 1", "", ""},
		{"quoted fatal text", "echo 'warning: sshd: no hostkeys available -- exiting.' >&2; exit 1", "", ""},
		{"different error", "echo other >&2; exit 1", "", ""},
		{"substring", "echo 'prefix " + privsepDiagnostic + "' >&2; exit 1", "", ""},
		{"signal", diagnostic + "kill -TERM $$", "", ""},
		{"stdout overflow", diagnostic + "head -c 300000 /dev/zero; exit 1", "", ""},
		{"stderr overflow", diagnostic + "head -c 5000 /dev/zero >&2; exit 1", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(root, "run"), 0o755))
			entry := filepath.Join(root, privsepPath)
			switch tc.entry {
			case "directory":
				require.NoError(t, os.Mkdir(entry, 0o755))
			case "file":
				require.NoError(t, os.WriteFile(entry, nil, 0o644))
			}
			fakeSSHD(t, root, tc.script)
			assert.Equal(t, sshdRun{reason: tc.reason}, runSSHDT(t.Context(), root, rootOwned))
			if tc.entry == "" {
				_, err := os.Lstat(entry)
				assert.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}

func TestRunSSHDTDeadlineClosesInheritedOutput(t *testing.T) {
	root := t.TempDir()
	fakeSSHD(t, root, "sleep 30 2>/dev/null &\nexit 0\n")
	start := time.Now()
	assert.Equal(t, sshdRun{reason: reasonSSHDTimeout}, runSSHDT(t.Context(), root, rootOwned))
	assert.Less(t, time.Since(start), sshdTimeout+2*time.Second)
}

func TestRunSSHDTWaitFailureReapsLeader(t *testing.T) {
	root := t.TempDir()
	fakeSSHD(t, root, "exec 1>&- 2>&-\nexec sleep 30\n")
	old := waitSSHD
	waitSSHD = func(int, int, *unix.Siginfo, int, *unix.Rusage) error { return unix.EPERM }
	t.Cleanup(func() { waitSSHD = old })
	start := time.Now()
	assert.Equal(t, sshdRun{}, runSSHDT(t.Context(), root, rootOwned))
	assert.Less(t, time.Since(start), sshdTimeout)
}

func TestPrivsepDerivationRequiresModeledInputs(t *testing.T) {
	const (
		main   = "etc/ssh/sshd_config"
		drop   = "etc/ssh/sshd_config.d/60-cloudimg-settings.conf"
		unit   = "usr/lib/systemd/system/ssh@.service"
		env    = "etc/default/ssh"
		status = "var/lib/dpkg/status"
	)
	type change struct{ name, path, content string }
	tests := []change{
		{"no service template", unit, ""},
		{"competing service", "lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D -f /etc/ssh/other"},
		{"non-ASCII service argument", unit, "[Service]\nExecStart=/usr/sbin/sshd\u00a0-i"},
		{"service options", unit, "[Service]\nExecStart=/usr/sbin/sshd -i -o PasswordAuthentication=yes"},
		{"service drop-in", "run/systemd/system/sshd@.service.d/override.conf", "[Service]\nExecStart=/usr/sbin/sshd -f /etc/ssh/other"},
		{"environment options", env, "SSHD_OPTS=-h /etc/ssh/other"},
		{"missing environment", env, ""},
		{"unknown expansion", unit, "[Service]\nExecStart=/usr/sbin/sshd -i $OPTIONS"},
		{"unreadable service", unit, "<directory>"},
		{"unreadable drop-in", "etc/systemd/system/ssh@.service.d/options.conf", "<directory>"},
		{"include inside match", main, "Match User guest\nInclude sshd_config.d/*.conf"},
		{"legacy package", status, "Package: openssh-server\nVersion: 1:8.6p1-1\nStatus: install ok installed\n"},
		{"missing package status", status, ""},
		{"unrecognized version", status, "Package: openssh-server\nVersion: 9.x\nStatus: install ok installed\n"},
		{"two list blocks", main, "Match Group staff\nAllowUsers one\nMatch LocalPort 22\nAllowUsers two"},
		{"single list block", main, "Match Group staff\nDenyGroups guests"},
		{"attached comment", drop, "AllowUsers guest#LEAKCANARY"},
		{"relative trusted CA", drop, "TrustedUserCAKeys etc/ca"},
		{"mixed none and absolute key paths", drop, "AuthorizedKeysFile none /etc/ssh/keys"},
		{"relative authorized keys", drop, "AuthorizedKeysFile /etc/ssh/keys keys/second"},
	}
	for _, alias := range []string{"ChallengeResponseAuthentication", "DSAAuthentication", "RSAAuthentication", "SKeyAuthentication", "PubkeyAcceptedKeyTypes", "AuthorizedKeysFile2"} {
		tests = append(tests, change{"alias " + alias, drop, "Match User guest\n" + alias + " no"})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			target := filepath.Join(root, tc.path)
			require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
			switch tc.content {
			case "":
				require.NoError(t, os.Remove(target))
			case "<directory>":
				if _, err := os.Lstat(target); err == nil {
					require.NoError(t, os.Remove(target))
				}
				require.NoError(t, os.Mkdir(target, 0o755))
			default:
				require.NoError(t, os.WriteFile(target, []byte(tc.content), 0o644))
			}
			r := newCollector(caseOptions(t, dir, spec, root, proc)).collect(t.Context())
			assert.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
			assert.Nil(t, r.SSHD.Effective)
			body, err := finalize(r)
			require.NoError(t, err)
			assert.NotContains(t, string(body), "LEAKCANARY")
		})
	}
}

func TestPrivsepStockConfigAndScalarMatch(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	c := newCollector(caseOptions(t, dir, spec, root, proc))
	want := make(map[string]*string, len(sshdDefaults))
	for key, v := range sshdDefaults {
		if v == "" {
			want[key] = nil
		} else {
			want[key] = &v
		}
	}
	want["passwordauthentication"], want["kbdinteractiveauthentication"] = ptr("no"), ptr("no")
	for _, withMatch := range []bool{false, true} {
		if withMatch {
			f, err := os.OpenFile(filepath.Join(root, sshdConfigPath), os.O_APPEND|os.O_WRONLY, 0)
			require.NoError(t, err)
			_, err = f.WriteString("\nMatch User guest\nPasswordAuthentication yes\n")
			require.NoError(t, err)
			require.NoError(t, f.Close())
		}
		r := c.collect(t.Context())
		assert.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
		assert.Equal(t, want, r.SSHD.Effective)
		if withMatch {
			require.Len(t, r.SSHD.MatchBlocks, 1)
			assert.Equal(t, "yes", r.SSHD.MatchBlocks[0].Sets["passwordauthentication"])
		}
	}
}

func TestSSHDProbePreservesConditionalAuthenticationAliases(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	opts := caseOptions(t, dir, spec, root, proc)
	opts.runSSHD = func(context.Context) sshdRun {
		return sshdRun{ok: true, out: []byte("kbdinteractiveauthentication no\n")}
	}
	write := func(value string) *exposureReport {
		require.NoError(t, os.WriteFile(filepath.Join(root, sshdConfigPath), []byte("Match User guest\n"+value), 0o644))
		return newCollector(opts).collect(t.Context())
	}
	r := write("ChallengeResponseAuthentication yes")
	assert.Equal(t, ptr("no"), r.SSHD.Effective["kbdinteractiveauthentication"])
	require.Len(t, r.SSHD.MatchBlocks, 1)
	assert.Equal(t, "yes", r.SSHD.MatchBlocks[0].Sets["kbdinteractiveauthentication"])
	r = write("AllowUsers guest#LEAKCANARY")
	assert.Nil(t, r.SSHD.Effective)
	assert.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDMatchUnsupported)
	body, err := finalize(r)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "LEAKCANARY")
}
