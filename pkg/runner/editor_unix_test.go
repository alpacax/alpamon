//go:build !windows

package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// killGroupOnCleanup kills the child's group unless the reaper already closed
// done: a reaped pid is free for reuse, so the group may no longer be ours.
func killGroupOnCleanup(t *testing.T, cmd *exec.Cmd, done <-chan struct{}) {
	t.Helper()

	pgid := cmd.Process.Pid
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}

		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("process group %d outlived the test", pgid)
		}
	})
}

// newManagerWithProcess puts the child in its own process group, so
// terminateProcess signals it and not the test binary.
func newManagerWithProcess(t *testing.T) (*CodeServerManager, *exec.Cmd) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	cmd := exec.CommandContext(ctx, "sleep", "300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())

	waitDone := reapProcess(cmd)
	killGroupOnCleanup(t, cmd, waitDone)

	m := &CodeServerManager{
		cmd:         cmd,
		waitDone:    waitDone,
		ctx:         ctx,
		cancel:      cancel,
		status:      CodeServerStatusStarting,
		stopGrace:   codeServerStopGrace,
		terminateFn: terminateProcess,
	}
	return m, cmd
}

// newManagerWithScript reads the "ready" line the script prints: a signal arriving
// before the script installs its trap would kill it by the default disposition.
func newManagerWithScript(t *testing.T, script string) (*CodeServerManager, *exec.Cmd, *bufio.Reader) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// os.Pipe, not cmd.StdoutPipe: the read end stays ours, so reading does not
	// race the cmd.Wait() the reaper runs concurrently.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	cmd.Stdout = pw
	t.Cleanup(func() { _ = pr.Close() })

	require.NoError(t, cmd.Start())
	require.NoError(t, pw.Close())

	waitDone := reapProcess(cmd)
	killGroupOnCleanup(t, cmd, waitDone)

	child := bufio.NewReader(pr)
	line, err := child.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ready\n", line)

	m := &CodeServerManager{
		cmd:         cmd,
		waitDone:    waitDone,
		ctx:         ctx,
		cancel:      cancel,
		status:      CodeServerStatusStarting,
		stopGrace:   codeServerStopGrace,
		terminateFn: terminateProcess,
	}
	return m, cmd, child
}

// TestStopBeforeStarted covers doStart's waitForReady failure path: it calls
// Stop before m.started is set—gating teardown on that flag leaks the process.
func TestStopBeforeStarted(t *testing.T) {
	m, cmd := newManagerWithProcess(t)

	require.NoError(t, m.Stop())

	require.NotNil(t, cmd.ProcessState, "Stop must terminate and reap the process")
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, ws.Signaled(), "the process should have died from a signal, not exited on its own")
	assert.Equal(t, syscall.SIGTERM, ws.Signal(), "Stop should terminate gracefully before falling back to SIGKILL")
	assert.ErrorIs(t, m.ctx.Err(), context.Canceled, "Stop must cancel the manager context")
}

// TestStopTwice mirrors tunnel_client stopping a manager that doStart already
// stopped on its failure path.
func TestStopTwice(t *testing.T) {
	m, _ := newManagerWithProcess(t)

	require.NoError(t, m.Stop())
	require.NoError(t, m.Stop(), "the second Stop must be a no-op, not another signal at a reaped pid")
	assert.Nil(t, m.cmd, "Stop must clear m.cmd so a later Stop has nothing to signal")
}

// TestStopWithoutProcess covers Stop during the install phase, which must abort
// installCodeServer through the context.
func TestStopWithoutProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	m := &CodeServerManager{ctx: ctx, cancel: cancel, status: CodeServerStatusInstalling}

	require.NoError(t, m.Stop())
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "Stop must cancel the context even with no process to signal")
}

func TestStopClearsRunningState(t *testing.T) {
	m, _ := newManagerWithProcess(t)
	m.started = true

	require.NoError(t, m.Stop())
	assert.False(t, m.IsRunning(), "Stop must clear m.started")
}

// TestStopKeepsStatusAnswerable pins Stop inside its wait with a child that
// ignores SIGTERM and reports it, so no sleep or deadline is needed.
func TestStopKeepsStatusAnswerable(t *testing.T) {
	m, cmd, child := newManagerWithScript(t,
		`trap 'echo signalled' TERM; echo ready; while :; do sleep 1; done`)

	stopped := make(chan error, 1)
	go func() {
		stopped <- m.Stop()
	}()

	line, err := child.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "signalled\n", line, "the child should have reported the SIGTERM Stop sent")

	require.True(t, m.mu.TryRLock(), "Stop must release m.mu before waiting on the process")
	m.mu.RUnlock()

	status, _ := m.Status()
	assert.Equal(t, CodeServerStatusStarting, status)

	require.NoError(t, syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL))
	require.NoError(t, <-stopped)
}

// TestStopWaitsAfterSignalFailure: a signal that does not land still leaves a child to collect.
func TestStopWaitsAfterSignalFailure(t *testing.T) {
	m, cmd := newManagerWithProcess(t)

	// Kills the child from inside the failing call, so the reap cannot land first.
	m.terminateFn = func(p *os.Process) error {
		_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
		return syscall.ESRCH
	}

	require.NoError(t, m.Stop(), "a failed signal is not a failure to stop")
	require.NotNil(t, cmd.ProcessState, "Stop returned before the process was reaped")
}

// TestWaitForReadySurvivesConcurrentStop covers TunnelClient.Close mid-startup, where Stop clears m.cmd.
func TestWaitForReadySurvivesConcurrentStop(t *testing.T) {
	m, _ := newManagerWithProcess(t)

	// Nothing listens on it, so every dial fails and the loop keeps running.
	port, err := findAvailablePort()
	require.NoError(t, err)
	m.port = port

	// Read before Stop nils the field, not from inside the goroutine.
	waitDone := m.waitDone
	ready := make(chan error, 1)
	go func() {
		ready <- m.waitForReady(waitDone)
	}()

	require.NoError(t, m.Stop())
	assert.ErrorContains(t, <-ready, "exited unexpectedly")
}

// TestStopKillsGroupIgnoringSIGTERM: on timeout the whole group must die.
// exec.CommandContext's own kill reaches only the leader.
func TestStopKillsGroupIgnoringSIGTERM(t *testing.T) {
	// Both shells ignore SIGTERM, so only SIGKILL at the group ends them.
	m, _, child := newManagerWithScript(t,
		`trap '' TERM; sh -c "trap '' TERM; while :; do sleep 1; done" & echo ready; while :; do sleep 1; done`)
	m.stopGrace = 200 * time.Millisecond

	require.ErrorContains(t, m.Stop(), "did not exit within")

	// Both shells hold the write end, so EOF means both are gone. kill(-pgid, 0)
	// would not do: it still finds a zombie that a container init never reaps.
	drained := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(child)
		drained <- err
	}()

	select {
	case err := <-drained:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop gave up on the process group but left it running")
	}
}

func TestSetupUserDataDirRefusesSymlinkedFiles(t *testing.T) {
	cfg := GetCodeServerConfig()
	for _, rel := range []string{"config.yaml", filepath.Join("User", "settings.json")} {
		t.Run(rel, func(t *testing.T) {
			homeDir := t.TempDir()
			target := filepath.Join(t.TempDir(), "victim")
			require.NoError(t, os.WriteFile(target, []byte("keep"), 0600))

			link := filepath.Join(homeDir, cfg.UserDataDirName, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(link), 0755))
			require.NoError(t, os.Symlink(target, link))

			_, err := setupUserDataDir(t.Context(), homeDir, "", "")
			assert.Error(t, err)

			data, err := os.ReadFile(target)
			require.NoError(t, err)
			assert.Equal(t, "keep", string(data))
		})
	}
}

func TestSetupUserDataDirRefusesSymlinkedDirs(t *testing.T) {
	cfg := GetCodeServerConfig()
	for _, rel := range []string{".", "User"} {
		t.Run(rel, func(t *testing.T) {
			homeDir := t.TempDir()
			target := t.TempDir()

			link := filepath.Join(homeDir, cfg.UserDataDirName, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(link), 0755))
			require.NoError(t, os.Symlink(target, link))

			_, err := setupUserDataDir(t.Context(), homeDir, "", "")
			assert.Error(t, err)

			entries, err := os.ReadDir(target)
			require.NoError(t, err)
			assert.Empty(t, entries, "nothing may be written through the symlinked directory")
		})
	}
}

// TestSetupUserDataDirFollowsASymlinkedHome covers a home directory an admin
// pointed at another filesystem. That entry is not the user's to swap, so the
// link is followed; the refusals below it are what the other tests pin.
func TestSetupUserDataDirFollowsASymlinkedHome(t *testing.T) {
	target := t.TempDir()
	homeDir := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.Symlink(target, homeDir))

	userDataDir, err := setupUserDataDir(t.Context(), homeDir, "", "")
	require.NoError(t, err)

	cfg := GetCodeServerConfig()
	assert.Equal(t, filepath.Join(homeDir, cfg.UserDataDirName), userDataDir)
	assert.FileExists(t, filepath.Join(target, cfg.UserDataDirName, "config.yaml"),
		"the files belong in the directory the link points at")
}

// TestChownUserDataDirDoesNotFollowSymlinks plants a symlink to a file the
// target user must not own. As root the file is created in the temp dir; as a
// regular user /etc/passwd stands in, where following the link would fail with
// EPERM.
func TestChownUserDataDirDoesNotFollowSymlinks(t *testing.T) {
	userDataDir := t.TempDir()

	target := "/etc/passwd"
	if os.Getuid() == 0 {
		target = filepath.Join(t.TempDir(), "victim")
		require.NoError(t, os.WriteFile(target, []byte("keep"), 0600))
	}
	beforeTarget := fileOwner(t, target)

	link := filepath.Join(userDataDir, "x")
	require.NoError(t, os.Symlink(target, link))
	beforeLink := fileOwner(t, link)

	// A witness with one name only, so the assertions above cannot pass by the
	// walk having re-owned nothing at all.
	ordinary := filepath.Join(userDataDir, "ordinary")
	require.NoError(t, os.WriteFile(ordinary, nil, 0600))
	username, groupname := movableOwnership(t, ordinary)
	beforeOrdinary := fileOwner(t, ordinary)

	require.NoError(t, chownUserDataDir(t.Context(), userDataDir, username, groupname))

	assert.Equal(t, beforeTarget, fileOwner(t, target), "a symlink target must keep its owner")
	assert.Equal(t, beforeLink, fileOwner(t, link), "the link itself is not the walk's to re-own either")
	assert.NotEqual(t, beforeOrdinary, fileOwner(t, ordinary),
		"the walk must still re-own the files this tree is the only name for")
}

// fileOwner reads both ids, since a non-root process can only ever move the
// group, and a test that watched the uid alone would pass without chowning.
// Lstat, not Stat: on a symlink the ownership under test is the link's own.
func fileOwner(t *testing.T, path string) [2]uint32 {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	st := info.Sys().(*syscall.Stat_t)
	return [2]uint32{st.Uid, st.Gid}
}

// movableOwnership returns a user and group chownUserDataDir can actually move
// an entry at path to: as root any account, and as a regular user their own
// name plus a group they belong to that the file is not already in—the only
// ownership change the kernel lets them make.
func movableOwnership(t *testing.T, path string) (username, groupname string) {
	t.Helper()

	if os.Getuid() == 0 {
		// Not every distro image ships "nobody" (opensuse/leap:15 does not).
		if _, err := user.Lookup("nobody"); err != nil {
			t.Skipf("no nobody account on this system: %v", err)
		}
		return "nobody", ""
	}

	current, err := user.Current()
	require.NoError(t, err)
	gids, err := current.GroupIds()
	require.NoError(t, err)
	own := strconv.FormatUint(uint64(fileOwner(t, path)[1]), 10)

	for _, gid := range gids {
		if gid == own {
			continue
		}
		if group, err := user.LookupGroupId(gid); err == nil {
			return current.Username, group.Name
		}
	}
	t.Skip("the current user belongs to no group other than the one already on the file")
	return "", ""
}

// TestWriteFileAtReplacesInPlaceFile proves the swap is atomic from the reader's
// side: a second link to the old inode keeps the old bytes, which an in-place
// truncate would have destroyed, and no temp file survives the call.
func TestWriteFileAtReplacesInPlaceFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f"), []byte("old"), 0644))
	require.NoError(t, os.Link(filepath.Join(dir, "f"), filepath.Join(dir, "witness")))

	parent, err := openDir(dir, dirFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = parent.Close() })

	require.NoError(t, writeFileAt(parent, "f", []byte("new")))

	kept, err := os.ReadFile(filepath.Join(dir, "witness"))
	require.NoError(t, err)
	assert.Equal(t, "old", string(kept), "the replaced file must keep the bytes a reader already had open")

	got, err := os.ReadFile(filepath.Join(dir, "f"))
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	assert.ElementsMatch(t, []string{"f", "witness"}, names, "the temp file must not outlive the write")
}

// TestWriteFileAtKeepsTheModeItReplaces: the renamed file arrives with the temp
// file's mode, so a tightened settings.json widens again on the next start
// unless the old mode is carried over. The mode and the umask are chosen to
// disagree, since a carry-over resting on O_CREAT alone narrows instead.
func TestWriteFileAtKeepsTheModeItReplaces(t *testing.T) {
	previous := unix.Umask(0077)
	t.Cleanup(func() { unix.Umask(previous) })

	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0644))
	require.NoError(t, os.Chmod(target, 0644))

	parent, err := openDir(dir, dirFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = parent.Close() })

	require.NoError(t, writeFileAt(parent, "f", []byte("new")))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "the replacement keeps the mode it replaced")
}

// nameLimit returns the longest file name dir accepts. NAME_MAX is not portable
// to query from Go here—unix.Pathconf exists on darwin and not on linux—so the
// limit is found by bisecting between one character and a length no filesystem
// in use accepts. The upper bound is asserted rather than assumed.
func nameLimit(t *testing.T, dir string) int {
	t.Helper()

	fits := func(n int) bool {
		path := filepath.Join(dir, strings.Repeat("n", n))
		if err := os.WriteFile(path, nil, 0600); err != nil {
			return false
		}
		require.NoError(t, os.Remove(path))
		return true
	}

	lo, hi := 1, 4097
	require.True(t, fits(lo))
	require.False(t, fits(hi), "no name length is rejected, so this test cannot fail the temp create")
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

// TestWriteFileAtLeavesNothingWhenTheTempWriteFails pins the failure path: the
// call must not create the target it never managed to fill. The name sits just
// under what the filesystem accepts, so it fits while the longer temp name
// derived from it does not, which fails the temp create and nothing else.
func TestWriteFileAtLeavesNothingWhenTheTempWriteFails(t *testing.T) {
	dir := t.TempDir()
	parent, err := openDir(dir, dirFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = parent.Close() })

	// The temp name adds a leading dot, a separating dot, at least one base36
	// digit and ".tmp", so three under the limit is enough to push it over.
	name := strings.Repeat("n", nameLimit(t, dir)-3)

	require.Error(t, writeFileAt(parent, name, []byte("x")))

	_, err = os.Stat(filepath.Join(dir, name))
	assert.ErrorIs(t, err, os.ErrNotExist, "a write that failed must leave no file at the target")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "the temp file must not survive the failure either")
}

func TestSetupUserDataDir(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Call setupUserDataDir (empty username/groupname since we're not running as root in tests)
	userDataDir, err := setupUserDataDir(t.Context(), tempDir, "", "")
	assert.NoError(t, err, "setupUserDataDir should not error")
	assert.NotEmpty(t, userDataDir, "userDataDir should not be empty")

	// Verify user data directory was created
	cfg := GetCodeServerConfig()
	expectedUserDataDir := filepath.Join(tempDir, cfg.UserDataDirName)
	assert.Equal(t, expectedUserDataDir, userDataDir)
	_, err = os.Stat(userDataDir)
	assert.NoError(t, err, "User data directory should exist")

	// Verify config.yaml was created
	configPath := filepath.Join(userDataDir, "config.yaml")
	configData, err := os.ReadFile(configPath)
	assert.NoError(t, err, "config.yaml should exist and be readable")
	assert.Contains(t, string(configData), "auth: none", "config.yaml should contain auth: none")
	assert.Contains(t, string(configData), "disable-telemetry: true", "config.yaml should contain disable-telemetry")
	assert.Contains(t, string(configData), "disable-update-check: true", "config.yaml should contain disable-update-check")

	// Verify User subdirectory was created
	userDir := filepath.Join(userDataDir, "User")
	_, err = os.Stat(userDir)
	assert.NoError(t, err, "User subdirectory should exist")

	// Verify settings.json was created
	settingsPath := filepath.Join(userDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	assert.NoError(t, err, "settings.json should exist and be readable")

	// Verify settings.json content
	var settings map[string]any
	err = json.Unmarshal(data, &settings)
	assert.NoError(t, err, "settings.json should be valid JSON")

	assert.Equal(t, cfg.ColorTheme, settings["workbench.colorTheme"], "colorTheme should match config")
	assert.Equal(t, "none", settings["workbench.startupEditor"], "workbench.startupEditor should be 'none'")
	assert.Equal(t, false, settings["workbench.welcomePage.walkthroughs.openOnInstall"], "walkthroughs should be disabled")
	assert.Equal(t, "none", settings["window.restoreWindows"], "window.restoreWindows should be 'none'")
	assert.Equal(t, "off", settings["telemetry.telemetryLevel"], "telemetry should be off")
	assert.Equal(t, false, settings["security.workspace.trust.enabled"], "workspace trust should be disabled")
	assert.Equal(t, "none", settings["update.mode"], "update.mode should be 'none'")
}

func TestSetupUserDataDirIdempotent(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Call setupUserDataDir twice
	userDataDir1, err := setupUserDataDir(t.Context(), tempDir, "", "")
	assert.NoError(t, err)

	userDataDir2, err := setupUserDataDir(t.Context(), tempDir, "", "")
	assert.NoError(t, err)

	// Both calls should return the same path
	assert.Equal(t, userDataDir1, userDataDir2)

	// settings.json should still be valid
	settingsPath := filepath.Join(userDataDir1, "User", "settings.json")
	data, err := os.ReadFile(settingsPath)
	assert.NoError(t, err)

	var settings map[string]any
	err = json.Unmarshal(data, &settings)
	assert.NoError(t, err)
	assert.Equal(t, "none", settings["workbench.startupEditor"])
}

// TestChownUserDataDirSkipsHardLinkedFiles: AT_SYMLINK_NOFOLLOW speaks for
// symlinks only. A hard link is a second name for one inode, and the user can
// plant one pointing at any file they can read, so chowning it would hand that
// file's ownership to them.
func TestChownUserDataDirSkipsHardLinkedFiles(t *testing.T) {
	userDataDir := t.TempDir()

	outside := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(outside, []byte("keep"), 0600))
	require.NoError(t, os.Link(outside, filepath.Join(userDataDir, "planted")))

	// A file with only this one name proves the walk re-owned anything at all,
	// so the assertion below cannot pass by the chown having been a no-op.
	ordinary := filepath.Join(userDataDir, "ordinary")
	require.NoError(t, os.WriteFile(ordinary, nil, 0600))

	username, groupname := movableOwnership(t, outside)
	beforeOutside := fileOwner(t, outside)
	beforeOrdinary := fileOwner(t, ordinary)

	require.NoError(t, chownUserDataDir(t.Context(), userDataDir, username, groupname))

	assert.Equal(t, beforeOutside, fileOwner(t, outside),
		"an inode that answers to another name outside the tree must keep its owner")
	assert.NotEqual(t, beforeOrdinary, fileOwner(t, ordinary),
		"the walk must still re-own the files this tree is the only name for")
}

// TestChownUserDataDirSkipsHardLinkedNonRegularFiles: link() does not care what
// type the inode is, and the kernel only refuses a source the caller does not
// own once fs.protected_hardlinks is set, which is not its own default. A
// socket or FIFO reached that way is the one worth planting, since handing it
// over lets the user chmod it and talk to whatever listens.
func TestChownUserDataDirSkipsHardLinkedNonRegularFiles(t *testing.T) {
	userDataDir := t.TempDir()

	outside := filepath.Join(t.TempDir(), "victim.fifo")
	require.NoError(t, unix.Mkfifo(outside, 0600))
	require.NoError(t, os.Link(outside, filepath.Join(userDataDir, "planted")))

	ordinary := filepath.Join(userDataDir, "ordinary")
	require.NoError(t, os.WriteFile(ordinary, nil, 0600))

	username, groupname := movableOwnership(t, outside)
	beforeOutside := fileOwner(t, outside)
	beforeOrdinary := fileOwner(t, ordinary)

	require.NoError(t, chownUserDataDir(t.Context(), userDataDir, username, groupname))

	assert.Equal(t, beforeOutside, fileOwner(t, outside),
		"a non-regular inode that answers to another name outside the tree must keep its owner")
	assert.NotEqual(t, beforeOrdinary, fileOwner(t, ordinary),
		"the walk must still re-own the files this tree is the only name for")
}

// TestChownUserDataDirStopsOnACancelledContext pins the narrow half: a walk
// handed a context that is already done re-owns nothing and says why. That the
// walk also stops once it is under way is TestEachNameStopsMidDirectory.
func TestChownUserDataDirStopsOnACancelledContext(t *testing.T) {
	userDataDir := t.TempDir()
	entry := filepath.Join(userDataDir, "f")
	require.NoError(t, os.WriteFile(entry, nil, 0600))

	username, groupname := movableOwnership(t, entry)
	beforeDir, beforeEntry := fileOwner(t, userDataDir), fileOwner(t, entry)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	assert.ErrorIs(t, chownUserDataDir(ctx, userDataDir, username, groupname), context.Canceled)
	assert.Equal(t, beforeDir, fileOwner(t, userDataDir), "the root of the tree is re-owned before any entry is")
	assert.Equal(t, beforeEntry, fileOwner(t, entry), "a cancelled walk must re-own nothing at all")
}

// TestEachNameStopsMidDirectory: a cancel that registered only before the first
// read would still let one closed session chown its way through a directory of
// any width, leaving another such walk behind on every open and close.
func TestEachNameStopsMidDirectory(t *testing.T) {
	dir := t.TempDir()
	for i := range readdirBatch + 1 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, strconv.Itoa(i)), nil, 0600))
	}

	parent, err := openDir(dir, dirFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = parent.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	seen := 0
	err = eachName(ctx, parent, func(string) error {
		seen++
		cancel()
		return nil
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, seen, "the cancel must land before the next entry, not at the next batch")
}

// TestChownUserDataDirStopsDescendingAtTheLimit: the walk holds one directory fd
// per level, which the agent shares with the WebSocket connection and the FTP
// sessions. It stops rather than fails, since readdir order decides whether the
// deep subtree comes before or after the settings.json that has to change hands.
func TestChownUserDataDirStopsDescendingAtTheLimit(t *testing.T) {
	root := t.TempDir()

	deepest := filepath.Join(root, "deep")
	for range maxChownDepth + 1 {
		deepest = filepath.Join(deepest, "d")
	}
	require.NoError(t, os.MkdirAll(deepest, 0755))

	sibling := filepath.Join(root, userDataSettingsFile)
	require.NoError(t, os.WriteFile(sibling, nil, 0600))

	username, groupname := movableOwnership(t, sibling)
	beforeSibling := fileOwner(t, sibling)
	beforeDeepest := fileOwner(t, deepest)

	require.NoError(t, chownUserDataDir(t.Context(), root, username, groupname))

	assert.NotEqual(t, beforeSibling, fileOwner(t, sibling),
		"a subtree too deep to enter must not cost the files beside it their owner")
	assert.Equal(t, beforeDeepest, fileOwner(t, deepest),
		"the walk must not descend past the descriptor budget")
}

// TestSetupUserDataDirRefusesAMissingHome pins the behavior for an account
// whose home directory is listed in passwd but absent from disk (an LDAP user,
// or useradd -M). The path-based MkdirAll this replaced created it root-owned,
// which left the user locked out of their own home; resolving one component at
// a time against a held fd cannot create it, so setup fails instead.
func TestSetupUserDataDirRefusesAMissingHome(t *testing.T) {
	homeDir := filepath.Join(t.TempDir(), "absent")

	_, err := setupUserDataDir(t.Context(), homeDir, "", "")

	assert.ErrorIs(t, err, os.ErrNotExist)
	_, statErr := os.Stat(homeDir)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "a missing home directory must not be created here")
}

// TestSetupUserDataDirUnderConcurrentSessions: one user opening two editor
// sessions sets the directory up twice at once, so every step has to tolerate a
// peer mid-flight—the mkdir that finds the directory there, the sweep that must
// leave a peer's temp alone, the rename onto a name someone else just claimed.
// What a reader sees mid-swap is TestWriteFileAtReplacesInPlaceFile's, since the
// read below runs only after every session has finished.
func TestSetupUserDataDirUnderConcurrentSessions(t *testing.T) {
	homeDir := t.TempDir()

	const sessions = 8
	start := make(chan struct{})
	errs := make(chan error, sessions)
	for range sessions {
		go func() {
			<-start
			_, err := setupUserDataDir(t.Context(), homeDir, "", "")
			errs <- err
		}()
	}
	close(start)
	for range sessions {
		require.NoError(t, <-errs)
	}

	cfg := GetCodeServerConfig()
	data, err := os.ReadFile(filepath.Join(homeDir, cfg.UserDataDirName, userDataUserDir, userDataSettingsFile))
	require.NoError(t, err)

	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings),
		"no session may leave the settings file behind half-written")
}

// TestSetupUserDataDirSweepsStaleTempFiles: a process killed between the temp
// create and the rename leaves the temp behind, and nothing else collects it.
// The sweep is bounded by age and by name so that neither a write in flight in
// another session nor an unrelated dot file is taken with it.
func TestSetupUserDataDirSweepsStaleTempFiles(t *testing.T) {
	homeDir := t.TempDir()
	userDataDir, err := setupUserDataDir(t.Context(), homeDir, "", "")
	require.NoError(t, err)

	aged := time.Now().Add(-2 * staleTempAge)
	abandoned := filepath.Join(userDataDir, tempPrefix(userDataConfigFile)+"abandoned"+tempSuffix)
	require.NoError(t, os.WriteFile(abandoned, nil, 0600))
	require.NoError(t, os.Chtimes(abandoned, aged, aged))

	unrelated := filepath.Join(userDataDir, ".editor-state"+tempSuffix)
	require.NoError(t, os.WriteFile(unrelated, nil, 0600))
	require.NoError(t, os.Chtimes(unrelated, aged, aged))

	inFlight := filepath.Join(userDataDir, tempPrefix(userDataConfigFile)+"inflight"+tempSuffix)
	require.NoError(t, os.WriteFile(inFlight, nil, 0600))

	_, err = setupUserDataDir(t.Context(), homeDir, "", "")
	require.NoError(t, err)

	_, err = os.Stat(abandoned)
	assert.ErrorIs(t, err, os.ErrNotExist, "an abandoned temp file must not outlive the next setup")
	assert.FileExists(t, inFlight, "a temp file another session is still filling must be left alone")
	assert.FileExists(t, unrelated, "the sweep must take only names writeFileAt could have made")
}

// TestSetupUserDataDirSurvivesAFifoNamedLikeATemp: the temp name is predictable
// and mkfifo needs no privilege, so the user can park a FIFO where the sweep
// will open it. An O_RDONLY open of a FIFO waits for a writer, and no signal
// reaches that wait, so a setup without O_NONBLOCK strands a goroutine inside
// the root agent on every editor start for that user.
func TestSetupUserDataDirSurvivesAFifoNamedLikeATemp(t *testing.T) {
	homeDir := t.TempDir()
	userDataDir, err := setupUserDataDir(t.Context(), homeDir, "", "")
	require.NoError(t, err)

	fifo := filepath.Join(userDataDir, tempPrefix(userDataConfigFile)+"fifo"+tempSuffix)
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	aged := time.Now().Add(-2 * staleTempAge)
	require.NoError(t, os.Chtimes(fifo, aged, aged))

	done := make(chan error, 1)
	go func() {
		_, err := setupUserDataDir(t.Context(), homeDir, "", "")
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("setupUserDataDir blocked opening the FIFO")
	}

	info, err := os.Lstat(fifo)
	require.NoError(t, err)
	assert.Equal(t, os.ModeNamedPipe, info.Mode()&os.ModeType, "the sweep must unlink only regular files")
}
