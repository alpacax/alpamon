//go:build linux

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// driverScript runs postinstall's upgrade path with every host-touching step stubbed out. The
// restart stub records whether the agent had already seen the upgrade command exit.
const driverScript = `
umask 022
POSTINSTALL_SOURCED=1
source "$POSTINSTALL"
check_root_permission() { :; }
check_systemd_status() { SYSTEMD_AVAILABLE=false; }
check_alpamon_binary() { :; }
cleanup_old_binary() { :; }
create_directories() { :; }
restart_alpamon_process() {
  if [ -e "$DIR/exited" ]; then echo after; else echo before; fi > "$DIR/restarted.tmp"
  mv "$DIR/restarted.tmp" "$DIR/restarted"
}
ALPAMON_LOG="$DIR/alpamon.log"
RESTART_GRACE="${GRACE:-1}" # the agent touches "exited" only after reaping the command and draining its output
RESTART_WAIT_LIMIT="$WAIT_LIMIT"
RESTART_TOKEN_FILE="${TOKEN_FILE:-$DIR/restart.token}"
set -e
main 2
`

// agentScript runs a command as pkg/executor does: own process group, output drained to EOF, group
// SIGKILLed after. The command plays a package manager that outlives its scriptlet by $HOLD seconds.
const agentScript = `
set -m
mkfifo "$DIR/out"
cat "$DIR/out" > "$DIR/output.txt" &
reader=$!
bash -c 'bash "$DIR/driver.sh"; sleep "$HOLD"' > "$DIR/out" 2>&1 &
command=$!
echo "$command" > "$DIR/command.pid"
wait "$command"
wait "$reader"
touch "$DIR/exited"
kill -KILL -- "-$command" 2>/dev/null || true
`

type upgradeRun struct {
	dir string
	env []string
}

func newUpgradeRun(t *testing.T, waitLimit, hold int) *upgradeRun {
	t.Helper()
	postinstall, err := filepath.Abs("postinstall.sh")
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "driver.sh"), []byte(driverScript), 0o600))
	return &upgradeRun{
		dir: dir,
		env: append(os.Environ(),
			"POSTINSTALL="+postinstall,
			"DIR="+dir,
			"WAIT_LIMIT="+strconv.Itoa(waitLimit),
			"HOLD="+strconv.Itoa(hold),
		),
	}
}

// startAgent runs the upgrade as a child of a process whose comm is "alpamon", the name
// postinstall's pkill matches. Wait returns once the agent has reaped and killed the command.
func (r *upgradeRun) startAgent(t *testing.T) *exec.Cmd {
	t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	agent := filepath.Join(r.dir, "alpamon")
	require.NoError(t, os.Symlink(bash, agent))

	cmd := exec.Command(agent, "-c", agentScript)
	cmd.Env = r.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if data, err := os.ReadFile(filepath.Join(r.dir, "command.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})
	return cmd
}

// restarted waits up to timeout for the restart stub and returns what it recorded.
func (r *upgradeRun) restarted(t *testing.T, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(filepath.Join(r.dir, "restarted"))
		if err == nil {
			return strings.TrimSpace(string(data))
		}
		require.ErrorIs(t, err, os.ErrNotExist)
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestSelfUpgradeWithoutSystemdRestartsOnlyAfterTheUpgradeCommandExits(t *testing.T) {
	// Given an agent-run upgrade whose package manager outlives the scriptlet by two seconds
	run := newUpgradeRun(t, 60, 2)

	// When the agent runs it, reaps it, and SIGKILLs its process group
	require.NoError(t, run.startAgent(t).Wait())

	// Then the restart still happens, and only after the agent saw the command exit
	assert.Equal(t, "after", run.restarted(t, 15*time.Second),
		"the restart must wait for the upgrade command to exit and survive the agent's group kill")
}

func TestSelfUpgradeWithoutSystemdCreatesAMissingLogOwnerAndGroupReadableOnly(t *testing.T) {
	// Given an agent-run upgrade on a host whose log file is gone, under umask 022
	run := newUpgradeRun(t, 60, 0)
	logPath := filepath.Join(run.dir, "alpamon.log")
	_, err := os.Stat(logPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	// When the deferred restart has run
	require.NoError(t, run.startAgent(t).Wait())
	require.NotEmpty(t, run.restarted(t, 15*time.Second))

	// Then the log it wrote to has the 0640 mode register.go gives it
	info, err := os.Stat(logPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestSelfUpgradeWithoutSystemdRestartsOnceTheWaitLimitPasses(t *testing.T) {
	// Given an agent-run upgrade whose command stays up well past a one-second wait limit
	run := newUpgradeRun(t, 1, 8)

	// When the agent runs it
	run.startAgent(t)

	// Then the restart happens while the command is still running instead of waiting forever
	assert.Equal(t, "before", run.restarted(t, 6*time.Second))
}

func TestUpgradeWithoutSystemdOutsideTheAgentRestartsBeforeReturning(t *testing.T) {
	// Given an upgrade an operator runs by hand, with no alpamon process among its ancestors
	run := newUpgradeRun(t, 60, 0)
	cmd := exec.Command("bash", filepath.Join(run.dir, "driver.sh"))
	cmd.Env = run.env

	// When postinstall runs
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	// Then the restart has already run by the time postinstall returns
	assert.FileExists(t, filepath.Join(run.dir, "restarted"))
}

func TestSelfUpgradeWithoutSystemdLeavesTheRestartToALaterUpgrade(t *testing.T) {
	// Given a deferred restart still in its grace when a second self-upgrade starts, both sharing one token file
	tokenFile := filepath.Join(t.TempDir(), "restart.token")
	first := newUpgradeRun(t, 60, 0)
	first.env = append(first.env, "GRACE=4", "TOKEN_FILE="+tokenFile)
	second := newUpgradeRun(t, 60, 0)
	second.env = append(second.env, "TOKEN_FILE="+tokenFile)
	require.NoError(t, first.startAgent(t).Wait())

	// When the second upgrade runs before the first job's grace ends
	require.NoError(t, second.startAgent(t).Wait())

	// Then only the later job restarts the agent
	assert.Equal(t, "after", second.restarted(t, 15*time.Second))
	assert.Empty(t, first.restarted(t, 6*time.Second), "the superseded job must not restart the agent again")
}

