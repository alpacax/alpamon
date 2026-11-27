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
			want := sshdRun{reason: tc.reason}
			if want.reason == reasonSSHDPrivsepMissing {
				want.binary = "/usr/sbin/sshd"
			}
			assert.Equal(t, want, runSSHDT(t.Context(), root, rootOwned))
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

func TestRunSSHDTDeadlineKillsLeaderWhenGroupIsGone(t *testing.T) {
	root := t.TempDir()
	fakeSSHD(t, root, "exec sleep 10")
	var group int
	signalSSHDGroup = func(pid int, sig unix.Signal) error {
		group = pid
		assert.Equal(t, unix.SIGKILL, sig)
		return unix.ESRCH
	}
	t.Cleanup(func() { signalSSHDGroup = unix.Kill })
	ctx, cancel := context.WithTimeoutCause(t.Context(), time.Second, errSSHDTimeout)
	defer cancel()
	start := time.Now()
	assert.Equal(t, sshdRun{reason: reasonSSHDTimeout}, runSSHDT(ctx, root, rootOwned))
	assert.Negative(t, group)
	assert.Less(t, time.Since(start), sshdTimeout)
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
		unit   = "usr/lib/systemd/system/ssh.service"
		env    = "etc/default/ssh"
		status = "var/lib/dpkg/status"
	)
	type change struct{ name, path, content string }
	tests := []change{
		{"quoted keyword", main, "\"PubkeyAuthentication\" yes\nPubkeyAuthentication no"},
		{"unknown keyword", main, "UnknownDirective yes"},
		{"unknown match keyword", main, "Match User guest\nUnknownDirective no"},
		{"invalid environment name", main, "AcceptEnv LANG=en"},
		{"unknown escape", main, `AcceptEnv LANG\q`},
		{"unrecognized whitespace", main, "\u00a0PubkeyAuthentication yes"},
		{"invalid repeated directive", main, "PubkeyAuthentication yes\nPubkeyAuthentication maybe"},
		{"non-ASCII glob pattern", main, "Include sshd_config.d/café?.conf"},
		{"relative revoked keys", drop, "RevokedKeys keys/revoked"},
		{"missing selected service", unit, ""},
		{"other sshd binary", unit, "[Service]\nExecStart=/usr/bin/sshd -D"},
		{"non-ASCII service argument", unit, "[Service]\nExecStart=/usr/sbin/sshd\u00a0-i"},
		{"service options", unit, "[Service]\nExecStart=/usr/sbin/sshd -i -o PasswordAuthentication=yes"},
		{"service drop-in", "run/systemd/system/ssh.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -f /etc/ssh/other"},
		{"unassigned optional environment", env, ""},
		{"comments-only environment", env, "# SSHD_OPTS= is not assigned"},
		{"carriage return in service", unit, "# comment\r[Service]\n[Service]\nExecStart=/usr/sbin/sshd -D"},
		{"carriage return in socket", "usr/lib/systemd/system/ssh.socket", "[Socket]\r\nListenStream=22"},
		{"carriage return in drop-in", "etc/systemd/system/ssh.service.d/options.conf", "# comment\r[Service]\rExecStart=/bin/other"},
		{"carriage return in environment", env, "SSHD_OPTS=\n# comment\rSSHD_OPTS=-f /other"},
		{"environment options", env, `SSHD_OPTS="-o PasswordAuthentication=yes"`},
		{"unreadable optional environment", env, "<directory>"},
		{"unknown expansion", unit, "[Service]\nExecStart=/usr/sbin/sshd -i $OPTIONS"},
		{"unreadable service", unit, "<directory>"},
		{"unreadable drop-in", "etc/systemd/system/ssh.service.d/options.conf", "<directory>"},
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
				require.NoError(t, os.Chtimes(target, fixtureMtime, fixtureMtime))
			}
			setFixtureTreeMtime(t, root)
			r := newCollector(caseOptions(t, dir, spec, root, proc)).collect(t.Context())
			assert.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
			assert.Nil(t, r.SSHD.Effective)
			body, err := finalize(r)
			require.NoError(t, err)
			assert.NotContains(t, string(body), "LEAKCANARY")
		})
	}
}

func TestPrivsepRequiresASCIIGlobCandidates(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	require.NoError(t, os.WriteFile(filepath.Join(root, sshdConfigPath), []byte("Include sshd_config.d/??.conf\nPasswordAuthentication no\n"), 0o644))
	c := newCollector(caseOptions(t, dir, spec, root, proc))
	collect := func() map[string]*string {
		t.Helper()
		r := c.collect(t.Context())
		require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
		return r.SSHD.Effective
	}
	require.Equal(t, ptr("no"), collect()["passwordauthentication"])
	for _, name := range []string{"é.conf", "\xff.conf"} {
		p := filepath.Join(root, "/etc/ssh/sshd_config.d", name)
		require.NoError(t, os.WriteFile(p, []byte("PasswordAuthentication yes\n"), 0o644))
		assert.Nil(t, collect())
		require.NoError(t, os.Remove(p))
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
	r := write(`"KbdInteractiveAuthentication" no`)
	assert.Equal(t, ptr("no"), r.SSHD.Effective["kbdinteractiveauthentication"])
	assert.NotContains(t, r.Categories[catSSHD].Reasons, reasonParseError)
	r = write("ChallengeResponseAuthentication yes")
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

func TestPrivsepSelectsEnabledSSHService(t *testing.T) {
	const (
		socket       = "usr/lib/systemd/system/ssh.socket"
		unit         = "usr/lib/systemd/system/ssh.service"
		template     = "usr/lib/systemd/system/ssh@.service"
		env          = "etc/default/ssh"
		safeTemplate = "[Service]\nExecStart=-/usr/sbin/sshd -i -4 -6 -e"
		unsafe       = "[Service]\nExecStart=/usr/sbin/sshd -f /etc/ssh/other"
		reset        = "[Service]\nExecStart=\nExecStart="
		socketLink   = "etc/systemd/system/sockets.target.wants/ssh.socket"
	)
	type inputs map[string]string
	for _, tc := range []struct {
		name   string
		files  inputs
		links  inputs
		derive bool
	}{
		{"stock socket and service", nil, nil, true},
		{"masked runtime socket", nil, inputs{"run/systemd/generator/ssh.socket": "/dev/null"}, false},
		{"generated socket", inputs{"run/systemd/generator/ssh.socket": "[Socket]\nAccept=no"}, nil, false},
		{"runtime service drop-in", inputs{"run/systemd/system.control/ssh.service.d/10.conf": "# unchanged options"}, nil, false},
		{"shadowed runtime enablement", nil, inputs{"run/systemd/system/sockets.target.wants/ssh.socket": "/usr/lib/systemd/system/ssh.socket"}, true},
		{"runtime enablement", nil, inputs{"run/systemd/system/sockets.target.requires/ssh.socket": "/usr/lib/systemd/system/ssh.socket"}, false},
		{"runtime service alias", inputs{socket: "[Socket]\nService=selected.service"}, inputs{"run/systemd/transient/selected.service": "/usr/lib/systemd/system/ssh.service"}, false},
		{"drop-in through runtime directory", inputs{"run/generated/10.conf": "# unchanged options"}, inputs{"etc/systemd/system/ssh.service.d": "/run/generated"}, false},
		{"runtime alias with drop-in", inputs{"etc/systemd/system/another.service.d/10.conf": "# alias options"}, inputs{"run/systemd/generator/another.service": "/usr/lib/systemd/system/ssh.service"}, false},
		{"merged library directory", inputs{socketLink: ""}, inputs{"lib": "usr/lib", socketLink: "/lib/systemd/system/ssh.socket"}, true},
		{"dangling enablement target", inputs{socketLink: ""}, inputs{socketLink: "/lib/systemd/system/ssh.socket"}, false},
		{"foreign enablement target", inputs{socketLink: "", "usr/lib/systemd/system/foreign.socket": "[Socket]\nAccept=no"}, inputs{socketLink: "/usr/lib/systemd/system/foreign.socket"}, false},
		{"shadowed enablement target", inputs{"etc/systemd/system/ssh.socket": "[Socket]\nAccept=no"}, nil, false},
		{"matching enablement alias", inputs{socketLink: ""}, inputs{"etc/systemd/system/alias.socket": "/usr/lib/systemd/system/ssh.socket", socketLink: "/etc/systemd/system/alias.socket"}, true},
		{"dangling direct service with enabled socket", nil, inputs{"etc/systemd/system/multi-user.target.wants/ssh.service": "/lib/systemd/system/ssh.service"}, false},
		{"conflicting requires target", inputs{"usr/lib/systemd/system/foreign.socket": "[Socket]\nAccept=no"}, inputs{"etc/systemd/system/sockets.target.requires/ssh.socket": "/usr/lib/systemd/system/foreign.socket"}, false},
		{"unselected template", inputs{template: unsafe}, nil, true},
		{"per connection", inputs{socket: "[Socket]\nAccept=yes", template: safeTemplate, unit: unsafe}, nil, true},
		{"socket service override", inputs{socket: "[Socket]\nService=local-ssh.service", unit: unsafe, "usr/lib/systemd/system/local-ssh.service": safeTemplate}, nil, true},
		{"service alias drop-in", inputs{"etc/systemd/system/sshd.service.d/options.conf": reset + "/usr/sbin/sshd -f /other"}, inputs{"etc/systemd/system/sshd.service": "/usr/lib/systemd/system/ssh.service"}, false},
		{"explicit service alias", inputs{socket: "[Socket]\nService=selected.service"}, inputs{"etc/systemd/system/selected.service": "/usr/lib/systemd/system/ssh.service"}, true},
		{"instance-specific override", inputs{socket: "[Socket]\nAccept=yes", template: safeTemplate, "etc/systemd/system/ssh@connection.service.d/options.conf": unsafe}, nil, false},
		{"unmodeled start preparation", inputs{unit: "[Service]\nExecStartPre=/usr/bin/prepare-ssh-config\nExecStart=/usr/sbin/sshd -D"}, nil, false},
		{"administrator prefix overrides vendor drop-in", inputs{socket: "[Socket]\nService=local-ssh.service", "usr/lib/systemd/system/local-ssh.service": safeTemplate,
			"usr/lib/systemd/system/local-ssh.service.d/50.conf": reset + "/usr/sbin/sshd -D",
			"etc/systemd/system/local-.service.d/50.conf":        reset + "/usr/sbin/sshd -o PasswordAuthentication=yes"}, nil, false},
		{"socket alias uses canonical service", inputs{socket: "", "usr/lib/systemd/system/other.socket": "[Socket]\nListenStream=22", "usr/lib/systemd/system/other.service": unsafe}, inputs{socket: "other.socket"}, false},
		{"instance override under template alias", inputs{socket: "[Socket]\nAccept=yes", template: safeTemplate, "etc/systemd/system/other@connection.service.d/options.conf": unsafe}, inputs{"etc/systemd/system/other@.service": "/usr/lib/systemd/system/ssh@.service"}, false},
		{"socket drop-in changes target", inputs{"etc/systemd/system/ssh.socket.d/target.conf": "[Socket]\nService=other.service", "usr/lib/systemd/system/other.service": unsafe}, nil, false},
		{"socket drop-in changes accept", inputs{"run/systemd/system/ssh.socket.d/accept.conf": "[Socket]\nAccept=yes", template: unsafe}, nil, false},
		{"two enabled sockets", inputs{"usr/lib/systemd/system/sshd.socket": "[Socket]\nAccept=no"}, inputs{"run/systemd/system/sockets.target.wants/sshd.socket": "/usr/lib/systemd/system/sshd.socket"}, false},
		{"direct enablement", inputs{socketLink: "", socket: "[Socket]\nService=other.service", "usr/lib/systemd/system/other.service": unsafe}, inputs{"etc/systemd/system/multi-user.target.wants/ssh.service": "/usr/lib/systemd/system/ssh.service"}, true},
		{"no enablement", inputs{socketLink: ""}, nil, false},
		{"hidden reset cannot mask unsafe service", inputs{unit: unsafe, "etc/systemd/system/ssh.service.d/.disabled.conf": reset + "/usr/sbin/sshd -D"}, nil, false},
		{"ignored drop-ins", inputs{"etc/systemd/system/ssh.service.d/.disabled.conf": unsafe, "etc/systemd/system/ssh.service.d/override.conf.dpkg-old": unsafe}, nil, true},
		{"optional file absent without expansion", inputs{env: "", unit: "[Service]\nEnvironmentFile=-/etc/default/ssh\nExecStart=/usr/sbin/sshd -D"}, nil, true},
		{"required file absent", inputs{unit: "[Service]\nEnvironmentFile=/etc/default/missing\nExecStart=/usr/sbin/sshd -D"}, nil, false},
		{"expanded flags", inputs{unit: "[Service]\nEnvironmentFile=/etc/default/ssh\nExecStart=-/usr/sbin/sshd -D ${SSHD_OPTS}", env: `SSHD_OPTS="-4 -e"`}, nil, true},
		{"unknown argument", inputs{unit: "[Service]\nExecStart=/usr/sbin/sshd -p 22"}, nil, false},
		{"environment reset", inputs{env: "SSHD_OPTS=-f /other", "etc/systemd/system/ssh.service.d/reset.conf": "[Service]\nEnvironmentFile=\nEnvironmentFile=-/etc/default/missing"}, nil, false},
		{"each effective environment file is checked", inputs{env: "SSHD_OPTS=-o PubkeyAuthentication=no", "run/systemd/system/ssh.service.d/options.conf": "[Service]\nEnvironmentFile=/etc/default/options", "etc/default/options": "SSHD_OPTS=-4"}, nil, false},
		{"service search priority", inputs{unit: unsafe, "run/systemd/system/ssh.service": unsafe, "etc/systemd/system/ssh.service": safeTemplate}, nil, true},
		{"drop-in directory precedence and lexical order", inputs{
			"usr/lib/systemd/system/ssh.service.d/50-start.conf": reset + "/usr/sbin/sshd -h /other",
			"run/systemd/system/ssh.service.d/50-start.conf":     reset + "/usr/sbin/sshd -h /other",
			"etc/systemd/system/ssh.service.d/50-start.conf":     reset + "/usr/sbin/sshd -i",
			"etc/systemd/system/ssh.service.d/10-early.conf":     reset + "/usr/sbin/sshd -f /other",
		}, nil, true},
		{"lexically later vendor override", inputs{
			"etc/systemd/system/ssh.service.d/10-start.conf":     reset + "/usr/sbin/sshd -i",
			"usr/lib/systemd/system/ssh.service.d/90-start.conf": reset + "/usr/sbin/sshd -f /other",
		}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			for file, data := range tc.files {
				p := filepath.Join(root, file)
				if data == "" {
					require.NoError(t, os.Remove(p))
					continue
				}
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
			}
			for file, target := range tc.links {
				p := filepath.Join(root, file)
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.Symlink(target, p))
			}
			setFixtureTreeMtime(t, root)
			r := newCollector(caseOptions(t, dir, spec, root, proc)).collect(t.Context())
			require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
			if tc.derive {
				require.Len(t, r.SSHD.Effective, len(sshdDefaults))
				assert.Equal(t, ptr("no"), r.SSHD.Effective["passwordauthentication"])
			} else {
				assert.Nil(t, r.SSHD.Effective)
			}
		})
	}
}

func TestPrivsepIgnoresRuntimeDirectoryTimestamps(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	afterBoot := time.Unix(spec.Btime+1, 0)
	for _, name := range []string{"system", "system.control", "transient", "generator", "generator.early", "generator.late"} {
		runtimeDir := filepath.Join(root, "/run/systemd", name)
		require.NoError(t, os.MkdirAll(filepath.Join(runtimeDir, "sockets.target.wants"), 0o755))
		require.NoError(t, os.Chtimes(runtimeDir, afterBoot, afterBoot))
		require.NoError(t, os.Chtimes(filepath.Join(runtimeDir, "sockets.target.wants"), afterBoot, afterBoot))
	}
	generator := filepath.Join(root, "/run/systemd/generator")
	require.NoError(t, os.WriteFile(filepath.Join(generator, "other.service"), []byte("[Service]\nExecStart=/bin/true"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(generator, "other.service.d"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(generator, "other.service.d/10.conf"), []byte("# unrelated"), 0o644))
	require.NoError(t, os.Symlink("/dev/null", filepath.Join(generator, "masked.service")))
	require.NoError(t, os.Mkdir(filepath.Join(generator, "masked.service.d"), 0o755))
	require.NoError(t, os.Symlink("generator", filepath.Join(root, "/run/systemd/system.attached")))
	r := newCollector(caseOptions(t, dir, spec, root, proc)).collect(t.Context())
	require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
	require.Len(t, r.SSHD.Effective, len(sshdDefaults))
	assert.Equal(t, ptr("no"), r.SSHD.Effective["passwordauthentication"])
}

func TestPrivsepIgnoresUnrelatedUnitUpdates(t *testing.T) {
	for _, unitDir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system"} {
		t.Run(unitDir, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			base := filepath.Join(root, unitDir)
			later := time.Unix(spec.Btime+1, 0)
			file := filepath.Join(base, "foo.service")
			require.NoError(t, os.WriteFile(file, []byte("[Service]\nExecStart=/bin/true"), 0o644))
			// The drop-in prompts the collector to check whether foo is an SSH alias.
			require.NoError(t, os.Mkdir(file+".d", 0o755))
			for _, kind := range []string{"wants", "requires"} {
				deps := filepath.Join(base, "sockets.target."+kind)
				require.NoError(t, os.MkdirAll(deps, 0o755))
				require.NoError(t, os.Symlink("../foo.service", filepath.Join(deps, "foo.service")))
				require.NoError(t, os.Chtimes(deps, later, later))
			}
			for _, p := range []string{file, file + ".d", base} {
				require.NoError(t, os.Chtimes(p, later, later))
			}
			r := newCollector(caseOptions(t, dir, spec, root, proc)).collect(t.Context())
			require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
			require.Len(t, r.SSHD.Effective, len(sshdDefaults))
			assert.Equal(t, ptr("no"), r.SSHD.Effective["passwordauthentication"])
		})
	}
}

func TestPrivsepRequiresServiceInputsFromBeforeBoot(t *testing.T) {
	for _, file := range []string{
		"usr/lib/systemd/system/ssh.socket",
		"usr/lib/systemd/system/ssh.service",
		"etc/systemd/system/ssh.socket.d/10.conf",
		"etc/systemd/system/ssh.service.d/10.conf",
		"etc/default/ssh",
		"etc/systemd/system/sockets.target.wants/ssh.socket",
		"etc/systemd/system/multi-user.target.wants/ssh.service",
		"etc/systemd/system/selected.service",
		"etc/systemd/system/ssh.socket.d",
		"etc/systemd/system/ssh.service.d",
	} {
		t.Run(file, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			p := filepath.Join(root, file)
			switch file {
			case "etc/systemd/system/multi-user.target.wants/ssh.service":
				require.NoError(t, os.Remove(filepath.Join(root, "etc/systemd/system/sockets.target.wants/ssh.socket")))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.Symlink("/usr/lib/systemd/system/ssh.service", p))
			case "etc/systemd/system/selected.service":
				require.NoError(t, os.WriteFile(filepath.Join(root, "usr/lib/systemd/system/ssh.socket"), []byte("[Socket]\nService=selected.service"), 0o644))
				require.NoError(t, os.Symlink("/usr/lib/systemd/system/ssh.service", p))
			}
			if strings.HasSuffix(file, ".conf") {
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte("# stock options\n"), 0o644))
			}
			if strings.HasSuffix(file, ".d") {
				require.NoError(t, os.MkdirAll(p, 0o755))
			}
			setFixtureTreeMtime(t, root)
			c := newCollector(caseOptions(t, dir, spec, root, proc))
			boot := time.Unix(spec.Btime, 0)
			for _, ts := range []time.Time{boot, boot.Add(time.Nanosecond)} {
				at := unix.NsecToTimespec(ts.UnixNano())
				require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{at, at}, unix.AT_SYMLINK_NOFOLLOW))
				r := c.collect(t.Context())
				require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
				assert.Equal(t, ts.Equal(boot), r.SSHD.Effective != nil)
			}
			require.NoError(t, os.Remove(filepath.Join(proc, "stat")))
			r := c.collect(t.Context())
			require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
			assert.Nil(t, r.SSHD.Effective)
		})
	}
}

func TestPrivsepDirectoryLinkTimestamps(t *testing.T) {
	for _, link := range []string{"usr/lib/systemd/system", "etc/systemd/system/ssh.service.d"} {
		t.Run(link, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			p := filepath.Join(root, link)
			require.NoError(t, os.MkdirAll(p, 0o755))
			require.NoError(t, os.Rename(p, p+"-target"))
			require.NoError(t, os.Symlink(filepath.Base(p)+"-target", p))
			setFixtureTreeMtime(t, root)
			c := newCollector(caseOptions(t, dir, spec, root, proc))
			require.Len(t, c.collect(t.Context()).SSHD.Effective, len(sshdDefaults))
			after := unix.Timespec{Sec: spec.Btime + 1}
			require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{after, after}, unix.AT_SYMLINK_NOFOLLOW))
			r := c.collect(t.Context())
			require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
			if strings.HasSuffix(link, ".d") {
				assert.Nil(t, r.SSHD.Effective)
			} else {
				assert.Len(t, r.SSHD.Effective, len(sshdDefaults))
			}
		})
	}
}

func TestPrivsepRejectsRemovedServiceDropIn(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts", "privsep-missing")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	drop := filepath.Join(root, "etc/systemd/system/ssh.service.d/override.conf")
	require.NoError(t, os.MkdirAll(filepath.Dir(drop), 0o755))
	require.NoError(t, os.WriteFile(drop, []byte("# service override\n"), 0o644))
	setFixtureTreeMtime(t, root)
	c := newCollector(caseOptions(t, dir, spec, root, proc))
	require.Len(t, c.collect(t.Context()).SSHD.Effective, len(sshdDefaults))
	require.NoError(t, os.Remove(drop))
	r := c.collect(t.Context())
	require.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDPrivsepMissing)
	assert.Nil(t, r.SSHD.Effective)
}

func TestSSHDExecStartPrefixes(t *testing.T) {
	for _, prefix := range []string{"", "-", "@", "+", "!", ":", "-+", "--"} {
		s := sshService{binary: "/usr/sbin/sshd", start: prefix + "/usr/sbin/sshd -D", starts: 1}
		assert.Equal(t, prefix == "" || prefix == "-", s.safeStart(t.Context(), mapSource{}), "prefix %q", prefix)
	}
}
