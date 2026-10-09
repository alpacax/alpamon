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
RESTART_LOCK_FILE="${LOCK_FILE:-$DIR/upgrade.lock}"
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
bash -c 'bash ${DRIVER_FLAGS-} "$DIR/driver.sh"; sleep "$HOLD"' > "$DIR/out" 2>&1 &
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

func (r *upgradeRun) log(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.dir, "alpamon.log"))
	require.NoError(t, err)
	return string(data)
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

	// Then the log it wrote to has the 0640 mode cmd/alpamon/command/register/service_linux.go gives it
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


func TestSelfUpgradeWithoutSystemdLeavesTheRestartToAManualUpgradeDuringItsGrace(t *testing.T) {
	// Given a deferred restart still in its grace, sharing its token file with an operator's upgrade
	tokenFile := filepath.Join(t.TempDir(), "restart.token")
	deferred := newUpgradeRun(t, 60, 0)
	deferred.env = append(deferred.env, "GRACE=3", "TOKEN_FILE="+tokenFile)
	manual := newUpgradeRun(t, 60, 0)
	manual.env = append(manual.env, "TOKEN_FILE="+tokenFile)
	require.NoError(t, deferred.startAgent(t).Wait())

	// When the operator upgrades by hand outside the agent
	cmd := exec.Command("bash", filepath.Join(manual.dir, "driver.sh"))
	cmd.Env = manual.env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	// Then the manual upgrade restarts the agent and the deferred job does not restart it again
	assert.FileExists(t, filepath.Join(manual.dir, "restarted"))
	assert.Empty(t, deferred.restarted(t, 6*time.Second))
	assert.Contains(t, deferred.log(t), "A later upgrade took over the deferred restart")
}

func TestSelfUpgradeWithoutSystemdStillRestartsInPOSIXModeWhenTheLockCannotBeOpened(t *testing.T) {
	// Given an agent-run upgrade under sh, as rpm runs scriptlets, whose lock directory is missing
	run := newUpgradeRun(t, 60, 0)
	run.env = append(run.env, "DRIVER_FLAGS=--posix", "LOCK_FILE="+filepath.Join(run.dir, "missing", "upgrade.lock"))

	// When the agent runs it
	require.NoError(t, run.startAgent(t).Wait())

	// Then the job survives the failed open and still restarts the agent
	assert.Equal(t, "after", run.restarted(t, 15*time.Second))
}

// holdLock takes the upgrade lock the way the agent's latch does and returns its release.
func holdLock(t *testing.T, path string) func() {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	return func() { _ = f.Close() }
}

func TestSelfUpgradeWithoutSystemdWaitsForTheUpgradeLockAndStandsDownForANewerToken(t *testing.T) {
	// Given a deferred restart whose grace ends while another upgrade holds the lock
	run := newUpgradeRun(t, 60, 0)
	lockFile := filepath.Join(run.dir, "upgrade.lock")
	tokenFile := filepath.Join(run.dir, "restart.token")
	run.env = append(run.env, "GRACE=2")
	release := holdLock(t, lockFile)
	defer release()
	require.NoError(t, run.startAgent(t).Wait())

	// When the grace passes
	// Then the job does not restart the agent mid-upgrade
	require.Empty(t, run.restarted(t, 5*time.Second))

	// And once the holder's own deferred restart replaced the token and released the lock, the job stands down
	require.NoError(t, os.WriteFile(tokenFile, []byte("newer\n"), 0o600))
	release()
	assert.Empty(t, run.restarted(t, 4*time.Second))
	assert.Contains(t, run.log(t), "A later upgrade took over the deferred restart")
}

func TestSelfUpgradeWithoutSystemdRestartsOnceTheUpgradeLockIsReleasedWithTheSameToken(t *testing.T) {
	// Given a deferred restart whose grace ends while another holder has the lock
	run := newUpgradeRun(t, 60, 0)
	run.env = append(run.env, "GRACE=2")
	release := holdLock(t, filepath.Join(run.dir, "upgrade.lock"))
	defer release()
	require.NoError(t, run.startAgent(t).Wait())
	require.Empty(t, run.restarted(t, 4*time.Second))

	// When the holder releases without a newer token
	release()

	// Then the job restarts the agent
	assert.Equal(t, "after", run.restarted(t, 10*time.Second))
}

func TestStartAlpamonProcessDoesNotPassTheUpgradeLockToTheNewAgent(t *testing.T) {
	// Given an agent binary that reports whether fd 9 is open, and fd 9 open in the caller
	dir := t.TempDir()
	postinstall, err := filepath.Abs("postinstall.sh")
	require.NoError(t, err)
	fakeAgent := filepath.Join(dir, "agent.sh")
	require.NoError(t, os.WriteFile(fakeAgent, []byte(
		"#!/bin/bash\nif [ -e /proc/self/fd/9 ]; then echo open; else echo closed; fi > \""+dir+"/fd9\"\nsleep 2\n"), 0o700))
	driver := `
POSTINSTALL_SOURCED=1
source "$POSTINSTALL"
create_log_file() { :; }
ALPAMON_BIN="$FAKE_AGENT"
ALPAMON_LOG="$DIR/alpamon.log"
exec 9>>"$DIR/upgrade.lock"
start_alpamon_process
`
	cmd := exec.Command("bash", "-c", driver)
	cmd.Env = append(os.Environ(), "POSTINSTALL="+postinstall, "FAKE_AGENT="+fakeAgent, "DIR="+dir)

	// When postinstall starts the new agent
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	// Then the agent does not hold fd 9
	data, err := os.ReadFile(filepath.Join(dir, "fd9"))
	require.NoError(t, err)
	assert.Equal(t, "closed", strings.TrimSpace(string(data)))
}
