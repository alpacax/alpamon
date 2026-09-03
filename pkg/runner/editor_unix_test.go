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

			_, err := setupUserDataDir(homeDir, "", "")
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

			_, err := setupUserDataDir(homeDir, "", "")
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

	userDataDir, err := setupUserDataDir(homeDir, "", "")
	require.NoError(t, err)

	cfg := GetCodeServerConfig()
	assert.Equal(t, filepath.Join(homeDir, cfg.UserDataDirName), userDataDir)
	assert.FileExists(t, filepath.Join(target, cfg.UserDataDirName, "config.yaml"),
		"the files belong in the directory the link points at")
}

// TestChownUserDataDirDoesNotFollowSymlinks plants a symlink to a file the
// target user must not own. As root the file is created in the temp dir and
// ownership goes to nobody; as a regular user /etc/passwd stands in, where
// following the link would fail with EPERM.
func TestChownUserDataDirDoesNotFollowSymlinks(t *testing.T) {
	userDataDir := t.TempDir()

	var target, username string
	if os.Getuid() == 0 {
		// Not every distro image ships "nobody" (opensuse/leap:15 does not).
		if _, err := user.Lookup("nobody"); err != nil {
			t.Skipf("no nobody account on this system: %v", err)
		}
		target = filepath.Join(t.TempDir(), "victim")
		require.NoError(t, os.WriteFile(target, []byte("keep"), 0600))
		username = "nobody"
	} else {
		target = "/etc/passwd"
		current, err := user.Current()
		require.NoError(t, err)
		username = current.Username
	}
	before := fileOwner(t, target)

	link := filepath.Join(userDataDir, "x")
	require.NoError(t, os.Symlink(target, link))

	require.NoError(t, chownUserDataDir(userDataDir, username, ""))

	assert.Equal(t, before, fileOwner(t, target), "symlink target must keep its owner")

	usr, err := user.Lookup(username)
	require.NoError(t, err)
	wantUID, err := strconv.Atoi(usr.Uid)
	require.NoError(t, err)
	linkInfo, err := os.Lstat(link)
	require.NoError(t, err)
	assert.Equal(t, uint32(wantUID), linkInfo.Sys().(*syscall.Stat_t).Uid, "the link itself is chowned")
}

// fileOwner reads both ids, since a non-root process can only ever move the
// group, and a test that watched the uid alone would pass without chowning.
func fileOwner(t *testing.T, path string) [2]uint32 {
	t.Helper()
	info, err := os.Stat(path)
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

// TestWriteFileAtKeepsTheModeItReplaces pins the mode across a replacement. The
// renamed file arrives with the temp file's mode, so the old one has to be
// carried over or a tightened settings.json widens again on the next start.
func TestWriteFileAtKeepsTheModeItReplaces(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0600))
	require.NoError(t, os.Chmod(target, 0600))

	parent, err := openDir(dir, dirFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = parent.Close() })

	require.NoError(t, writeFileAt(parent, "f", []byte("new")))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "the replacement keeps the mode it replaced")
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
	userDataDir, err := setupUserDataDir(tempDir, "", "")
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
	userDataDir1, err := setupUserDataDir(tempDir, "", "")
	assert.NoError(t, err)

	userDataDir2, err := setupUserDataDir(tempDir, "", "")
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

	require.NoError(t, chownUserDataDir(userDataDir, username, groupname))

	assert.Equal(t, beforeOutside, fileOwner(t, outside),
		"an inode that answers to another name outside the tree must keep its owner")
	assert.NotEqual(t, beforeOrdinary, fileOwner(t, ordinary),
		"the walk must still re-own the files this tree is the only name for")
}

// TestChownUserDataDirRefusesADeepTree: the walk holds one directory fd per
// level, and the agent shares its descriptors with the WebSocket connection
// and the FTP sessions, so a tree the user nested deep enough would take those
// down with it rather than merely failing the chown.
func TestChownUserDataDirRefusesADeepTree(t *testing.T) {
	root := t.TempDir()
	deep := root
	for range maxChownDepth + 1 {
		deep = filepath.Join(deep, "d")
	}
	require.NoError(t, os.MkdirAll(deep, 0755))

	current, err := user.Current()
	require.NoError(t, err)

	assert.ErrorContains(t, chownUserDataDir(root, current.Username, ""), "nests deeper than")
}
