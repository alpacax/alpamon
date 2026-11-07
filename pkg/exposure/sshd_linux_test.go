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
	assert.Equal(t, sshdRun{}, runSSHDT(context.Background(), root, notRoot), "a binary not owned by root is never run")
	assert.Empty(t, calls())

	require.NoError(t, os.Remove(filepath.Join(root, "usr/sbin/sshd")))
	require.NoError(t, os.Symlink("/bin/true", filepath.Join(root, "usr/sbin/sshd")))
	assert.False(t, runSSHDT(context.Background(), root, rootOwned).ok, "a symlinked binary is never run")
	assert.Empty(t, calls())
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
	assert.False(t, run.ok)
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
			case "StartProcess", "ForkExec", "Exec", "Command", "CommandContext":
				if f != "sshd_linux.go" {
					t.Errorf("%s calls %s", f, sel.Sel.Name)
				}
			}
			return true
		})
	}
}
