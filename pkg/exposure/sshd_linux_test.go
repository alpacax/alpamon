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
