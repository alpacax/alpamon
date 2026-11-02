//go:build linux || darwin

package runner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/executor"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/shell"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ansiballzProbe keeps the parts of AnsiballZ that touch the process (cwd fallback,
// realpath of __main__.__file__, a payload tempdir) and prints what the module sees as JSON.
const ansiballzProbe = `#!/usr/bin/python3
_ANSIBALLZ_WRAPPER = True
import json, os, sys, tempfile, __main__
try:
    os.getcwd()
except OSError:
    os.chdir(os.path.expanduser('~'))
scriptdir = os.path.dirname(os.path.realpath(__main__.__file__))
payload = tempfile.mkdtemp(prefix='ansible_probe_payload_')
os.rmdir(payload)
result = {"uid": os.getuid(), "home": os.environ.get("HOME"), "cwd": os.getcwd(), "argv": sys.argv[1:], "scriptdir": scriptdir}
if os.environ.get("PROBE_FAIL"):
    result.update(failed=True, msg="probe failed")
print(json.dumps(result))
sys.exit(1 if result.get("failed") else 0)
`

// recordingDispatcher runs commands through the real shell handler and keeps
// the result the runner would report to the server.
type recordingDispatcher struct {
	handler  *shell.ShellHandler
	exitCode int
	result   string
	calls    int
}

func (d *recordingDispatcher) Execute(ctx context.Context, command string, args *common.CommandArgs) (int, string, error) {
	d.calls++
	exitCode, result, err := d.handler.Execute(ctx, command, args)
	d.exitCode, d.result = exitCode, result
	return exitCode, result, err
}

func (d *recordingDispatcher) HasHandler(command string) bool {
	return command == common.ExecFile.String()
}

type probeResult struct {
	UID       int      `json:"uid"`
	Home      string   `json:"home"`
	Cwd       string   `json:"cwd"`
	Argv      []string `json:"argv"`
	Scriptdir string   `json:"scriptdir"`
	Failed    bool     `json:"failed"`
}

func skipUnlessRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("running as another account needs root")
	}
}

// accountWithGroup looks up name and its primary group name, skipping when the
// host has no such account.
func accountWithGroup(t *testing.T, name string) (*user.User, string) {
	t.Helper()
	usr, err := user.Lookup(name)
	if err != nil {
		t.Skipf("no %s account: %v", name, err)
	}
	grp, err := user.LookupGroupId(usr.Gid)
	require.NoError(t, err)
	return usr, grp.Name
}

// startDirFor is where the file lane starts an account's module: its home when
// that is a directory, otherwise /.
func startDirFor(usr *user.User) string {
	if info, err := os.Stat(usr.HomeDir); err == nil && info.IsDir() {
		return usr.HomeDir
	}
	return "/"
}

// runVerifiedFile stages content where put_file leaves a module, a run directory
// under remote_tmp made with umask 77, and runs it through the real runner.
func runVerifiedFile(t *testing.T, interpreter, name, content, username, groupname string, env map[string]string) *recordingDispatcher {
	t.Helper()
	runDir := filepath.Join(t.TempDir(), ".ansible", "tmp", "ansible-tmp-1793258330.5-85243-1121909")
	require.NoError(t, os.MkdirAll(runDir, 0o700))
	require.NoError(t, os.Chmod(filepath.Dir(filepath.Dir(runDir)), 0o700))
	path := filepath.Join(runDir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	sum := sha256.Sum256([]byte(content))
	data, err := json.Marshal(protocol.FileExecPayload{Path: path, Interpreter: interpreter, Args: []string{}, SHA256: "sha256:" + hex.EncodeToString(sum[:])})
	require.NoError(t, err)
	dispatcher := &recordingDispatcher{handler: shell.NewShellHandler(executor.NewExecutor())}
	cmd := protocol.Command{Shell: "file", User: username, Group: groupname, Env: env, Data: string(data)}

	require.NoError(t, runner.NewCommandRunner(nil, nil, cmd, protocol.CommandData{}, dispatcher).Run(context.Background()))

	require.Equal(t, 1, dispatcher.calls, "the verified file must reach execution")
	return dispatcher
}

func runAnsiballZ(t *testing.T, username, groupname string, env map[string]string) (*recordingDispatcher, probeResult) {
	t.Helper()
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	dispatcher := runVerifiedFile(t, interpreter, "AnsiballZ_probe.py", ansiballzProbe, username, groupname, env)
	var got probeResult
	require.NoError(t, json.Unmarshal([]byte(dispatcher.result), &got), "stdout must be the module's JSON alone: %q", dispatcher.result)
	return dispatcher, got
}

func TestFileLane_RunsAnsiballZAsTheBecomeAccountWhenRoot(t *testing.T) {
	skipUnlessRoot(t)
	become, group := accountWithGroup(t, "nobody")

	dispatcher, got := runAnsiballZ(t, become.Username, group, nil)

	assert.Equal(t, 0, dispatcher.exitCode)
	assert.Equal(t, become.Uid, strconv.Itoa(got.UID), "the module runs as the become account, not the agent")
	assert.Equal(t, become.HomeDir, got.Home, "HOME is the become account's, as sudo -H sets it")
	assert.Equal(t, startDirFor(become), got.Cwd)
	assert.Empty(t, got.Argv, "an empty args list must not reach the wrapper, which reads one argument as its debug mode")
	assert.NotContains(t, got.Scriptdir, ".ansible", "the module runs from the sealed copy, not the run directory it cannot read")
}

func TestFileLane_ReturnsAFailedModuleExitCodeAndJSONWhenRoot(t *testing.T) {
	skipUnlessRoot(t)
	become, group := accountWithGroup(t, "nobody")

	dispatcher, got := runAnsiballZ(t, become.Username, group, map[string]string{"PROBE_FAIL": "1"})

	assert.Equal(t, 1, dispatcher.exitCode)
	assert.True(t, got.Failed)
}

func TestFileLane_RunsAnsiballZAsRootFromRootsHomeWhenRoot(t *testing.T) {
	skipUnlessRoot(t)
	root, group := accountWithGroup(t, "root")

	dispatcher, got := runAnsiballZ(t, root.Username, group, nil)

	assert.Equal(t, 0, dispatcher.exitCode)
	assert.Equal(t, 0, got.UID)
	assert.Equal(t, root.HomeDir, got.Home)
	assert.Equal(t, startDirFor(root), got.Cwd)
}

func TestFileLane_RunsAsABecomeAccountWithoutAHomeFromTheRootDirectoryWhenRoot(t *testing.T) {
	skipUnlessRoot(t)
	become, group := accountWithGroup(t, "nobody")
	if info, err := os.Stat(become.HomeDir); err == nil && info.IsDir() {
		t.Skipf("%s has a home directory here", become.Username)
	}

	dispatcher := runVerifiedFile(t, "/bin/sh", "AnsiballZ_probe.sh", "pwd\n", become.Username, group, nil)

	assert.Equal(t, 0, dispatcher.exitCode, dispatcher.result)
	assert.Equal(t, "/\n", dispatcher.result)
}
