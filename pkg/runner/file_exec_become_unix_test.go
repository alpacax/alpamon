//go:build !windows

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

// ansiballzProbe keeps the parts of ansible-core's AnsiballZ wrapper that touch
// the process (cwd fallback, realpath of __main__.__file__, a payload tempdir)
// and reports what the module would see as Ansible's JSON result on stdout.
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

// stageAnsiballZ writes the probe where Ansible's put_file leaves a module: a
// run directory under the login account's remote_tmp, made with umask 77, so
// no other account can read it.
func stageAnsiballZ(t *testing.T) (path, digest string) {
	t.Helper()
	runDir := filepath.Join(t.TempDir(), ".ansible", "tmp", "ansible-tmp-1793258330.5-85243-1121909")
	require.NoError(t, os.MkdirAll(runDir, 0o700))
	require.NoError(t, os.Chmod(filepath.Dir(filepath.Dir(runDir)), 0o700))
	path = filepath.Join(runDir, "AnsiballZ_probe.py")
	require.NoError(t, os.WriteFile(path, []byte(ansiballzProbe), 0o600))
	sum := sha256.Sum256([]byte(ansiballzProbe))
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

// becomeAccount returns an unprivileged account that cannot read the run
// directory, as a become user other than the login account.
func becomeAccount(t *testing.T) (*user.User, string) {
	t.Helper()
	usr, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account to become: %v", err)
	}
	grp, err := user.LookupGroupId(usr.Gid)
	require.NoError(t, err)
	return usr, grp.Name
}

// workingDirFor is where a become account's module starts: its home, or / when
// the account has none, as sudo would leave a module that cannot use its home.
func workingDirFor(usr *user.User) string {
	if info, err := os.Stat(usr.HomeDir); err == nil && info.IsDir() {
		return usr.HomeDir
	}
	return "/"
}

func runAnsiballZ(t *testing.T, username, groupname string, env map[string]string) (*recordingDispatcher, probeResult) {
	t.Helper()
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	path, digest := stageAnsiballZ(t)
	data, err := json.Marshal(protocol.FileExecPayload{Path: path, Interpreter: interpreter, Args: []string{}, SHA256: digest})
	require.NoError(t, err)
	dispatcher := &recordingDispatcher{handler: shell.NewShellHandler(executor.NewExecutor())}
	cmd := protocol.Command{Shell: "file", Line: interpreter + " " + path, User: username, Group: groupname, Env: env, Data: string(data)}

	require.NoError(t, runner.NewCommandRunner(nil, nil, cmd, protocol.CommandData{}, dispatcher).Run(context.Background()))

	require.Equal(t, 1, dispatcher.calls, "the verified file must reach execution: %s", dispatcher.result)
	var got probeResult
	require.NoError(t, json.Unmarshal([]byte(dispatcher.result), &got), "stdout must be the module's JSON alone: %q", dispatcher.result)
	return dispatcher, got
}

func TestFileLane_RunsAnsiballZAsTheBecomeAccountWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("running as another account needs root")
	}
	become, group := becomeAccount(t)

	dispatcher, got := runAnsiballZ(t, become.Username, group, nil)

	assert.Equal(t, 0, dispatcher.exitCode)
	assert.Equal(t, strconv.Itoa(got.UID), become.Uid, "the module runs as the become account, not the agent")
	assert.Equal(t, become.HomeDir, got.Home, "HOME is the become account's, as sudo -H sets it")
	assert.Equal(t, workingDirFor(become), got.Cwd)
	assert.Empty(t, got.Argv, "an empty args list must not reach the wrapper, which reads one argument as its debug mode")
	assert.NotContains(t, got.Scriptdir, ".ansible", "the module runs from the sealed copy, not the run directory it cannot read")
}

func TestFileLane_ReturnsAFailedModuleExitCodeAndJSONWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("running as another account needs root")
	}
	become, group := becomeAccount(t)

	dispatcher, got := runAnsiballZ(t, become.Username, group, map[string]string{"PROBE_FAIL": "1"})

	assert.Equal(t, 1, dispatcher.exitCode)
	assert.True(t, got.Failed)
}

func TestFileLane_RunsAnsiballZAsRootWithRootsHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the root become account needs the agent to run as root")
	}

	root, err := user.Lookup("root")
	require.NoError(t, err)
	group, err := user.LookupGroupId(root.Gid)
	require.NoError(t, err)

	dispatcher, got := runAnsiballZ(t, "root", group.Name, nil)

	assert.Equal(t, 0, dispatcher.exitCode)
	assert.Equal(t, 0, got.UID)
	assert.Equal(t, root.HomeDir, got.Home)
}

func TestFileLane_RunsAsABecomeAccountWithoutAHomeFromTheRootDirectoryWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("running as another account needs root")
	}
	become, group := becomeAccount(t)
	if _, err := os.Stat(become.HomeDir); err == nil {
		t.Skipf("%s has a home directory here", become.Username)
	}
	script := []byte("pwd\n")
	path := filepath.Join(t.TempDir(), "AnsiballZ_probe.sh")
	require.NoError(t, os.WriteFile(path, script, 0o600))
	sum := sha256.Sum256(script)
	data, err := json.Marshal(protocol.FileExecPayload{Path: path, Interpreter: "/bin/sh", Args: []string{}, SHA256: "sha256:" + hex.EncodeToString(sum[:])})
	require.NoError(t, err)
	dispatcher := &recordingDispatcher{handler: shell.NewShellHandler(executor.NewExecutor())}
	cmd := protocol.Command{Shell: "file", User: become.Username, Group: group, Data: string(data)}

	require.NoError(t, runner.NewCommandRunner(nil, nil, cmd, protocol.CommandData{}, dispatcher).Run(context.Background()))

	assert.Equal(t, 0, dispatcher.exitCode, dispatcher.result)
	assert.Equal(t, "/\n", dispatcher.result)
}
