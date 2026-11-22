//go:build !windows

package runner

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeServerSysProcAttr_CarriesTheResolvedCredential(t *testing.T) {
	cred := &syscall.Credential{Uid: 501, Gid: 20}
	shared := &syscall.SysProcAttr{Credential: cred}

	attr := codeServerSysProcAttr(shared)

	assert.Same(t, cred, attr.Credential)
	assert.True(t, attr.Setpgid)
	assert.NotSame(t, shared, attr)
	assert.False(t, shared.Setpgid, "the manager's shared SysProcAttr must stay untouched")
}

func TestCodeServerSysProcAttr_NilKeepsTheCurrentUser(t *testing.T) {
	attr := codeServerSysProcAttr(nil)

	assert.Nil(t, attr.Credential)
	assert.True(t, attr.Setpgid)
}

// makeOpenTree builds a tree whose modes let group and other write, like the macOS release tarball.
func makeOpenTree(t *testing.T) (root, dir, file, link string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "code-server")
	dir = filepath.Join(root, "bin")
	file = filepath.Join(dir, "code-server")
	link = filepath.Join(root, "current")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(file, nil, 0644))
	require.NoError(t, os.Symlink(file, link))
	require.NoError(t, os.Chmod(file, 0777))
	require.NoError(t, os.Chmod(dir, 0777))
	require.NoError(t, os.Chmod(root, 0775))
	return root, dir, file, link
}

func TestSecureCodeServerTree_DropsGroupAndOtherWrite(t *testing.T) {
	root, dir, file, link := makeOpenTree(t)

	err := secureCodeServerTree(root, os.Getuid(), os.Getgid())

	require.NoError(t, err)
	for path, want := range map[string]os.FileMode{root: 0755, dir: 0755, file: 0755} {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, want, fi.Mode().Perm(), path)
	}
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, fi.Mode().Type())
}

func TestSecureCodeServerTree_GivesTheTreeToRootWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	root, dir, file, link := makeOpenTree(t)
	for _, p := range []string{root, dir, file, link} {
		require.NoError(t, os.Lchown(p, 501, 20)) // the owner macOS tar restores from the archive
	}

	err := secureCodeServerTree(root, 0, 0)

	require.NoError(t, err)
	for _, p := range []string{root, dir, file, link} {
		assert.Equal(t, [2]uint32{0, 0}, lstatOwner(t, p), p)
	}
}

func lstatOwner(t *testing.T, path string) [2]uint32 {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return [2]uint32{st.Uid, st.Gid}
}

func ownersOfTempDirs() []uint32 {
	return []uint32{0, uint32(os.Geteuid())} // the temp dir chain mixes root and the test user
}

func TestVerifyOwnedPath_AcceptsATreeOnlyTheOwnersCanChange(t *testing.T) {
	root, _, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))

	err := verifyOwnedPath(file, ownersOfTempDirs()...)

	assert.NoError(t, err)
}

func TestVerifyOwnedPath_RefusesAGroupWritableParent(t *testing.T) {
	root, dir, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))
	require.NoError(t, os.Chmod(dir, 0775))

	err := verifyOwnedPath(file, ownersOfTempDirs()...)

	assert.ErrorContains(t, err, "writable by group or other")
}

func TestVerifyOwnedPath_RefusesADirOwnedByAnotherAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the temp files, so they are not foreign")
	}
	root, _, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))

	err := verifyOwnedPath(file, 0)

	assert.ErrorContains(t, err, "which is not allowed")
}

func TestVerifyOwnedPath_RefusesAFileOwnedByAnotherAccountWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	root, _, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, 0, 0))
	require.NoError(t, os.Lchown(file, 501, 20)) // only the file leaves root, so the dir chain passes

	err := verifyOwnedPath(file, ownersOfTempDirs()...)

	assert.ErrorContains(t, err, "owned by uid 501")
}

func TestVerifyOwnedPath_ChecksTheSymlinkTarget(t *testing.T) {
	root, dir, _, link := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))
	require.NoError(t, os.Chmod(dir, 0777)) // the link's own dir stays safe; its target's does not

	err := verifyOwnedPath(link, ownersOfTempDirs()...)

	assert.ErrorContains(t, err, "writable by group or other")
}

func TestLockCodeServerPrefix_CreatesAnOwnerOnlyDir(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "opt", "alpamon", "code-server") // /opt is missing on some Macs

	oldMask := syscall.Umask(0077) // the parent must still let demoted users through
	err := lockCodeServerPrefix(prefix, os.Getuid(), os.Getgid())
	syscall.Umask(oldMask)

	require.NoError(t, err)
	fi, err := os.Stat(prefix)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
	for _, dir := range []string{filepath.Dir(prefix), filepath.Dir(filepath.Dir(prefix))} {
		fi, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0755), fi.Mode().Perm(), dir)
	}
}

func TestLockCodeServerPrefix_ClosesAnExistingInstall(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "code-server")
	require.NoError(t, os.Mkdir(prefix, 0755))

	err := lockCodeServerPrefix(prefix, os.Getuid(), os.Getgid())

	require.NoError(t, err)
	fi, err := os.Stat(prefix)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
}

func TestLockCodeServerPrefix_RefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.Mkdir(target, 0755))
	prefix := filepath.Join(dir, "code-server")
	require.NoError(t, os.Symlink(target, prefix))

	err := lockCodeServerPrefix(prefix, os.Getuid(), os.Getgid())

	assert.ErrorContains(t, err, "is not a directory")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), fi.Mode().Perm())
}

func TestLockCodeServerPrefix_GivesThePrefixToRootWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	prefix := filepath.Join(t.TempDir(), "code-server")
	require.NoError(t, os.Mkdir(prefix, 0755))
	require.NoError(t, os.Lchown(prefix, 501, 20))

	err := lockCodeServerPrefix(prefix, 0, 0)

	require.NoError(t, err)
	assert.Equal(t, [2]uint32{0, 0}, lstatOwner(t, prefix))
}

func TestInstallRootOwnedCodeServer_InstallsBehindAClosedPrefixAndOpensItAfter(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "code-server")
	bin := filepath.Join(prefix, "bin", "code-server")
	var modeDuringInstall os.FileMode
	install := func() error {
		fi, err := os.Stat(prefix)
		if err != nil {
			return err
		}
		modeDuringInstall = fi.Mode().Perm()
		if err := os.MkdirAll(filepath.Dir(bin), 0777); err != nil {
			return err
		}
		if err := os.WriteFile(bin, nil, 0777); err != nil {
			return err
		}
		return os.Chmod(bin, 0777) // what an archive may carry past the umask
	}

	err := installRootOwnedCodeServer(prefix, os.Getuid(), os.Getgid(), install)

	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), modeDuringInstall)
	fi, err := os.Stat(prefix)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), fi.Mode().Perm())
	fi, err = os.Stat(bin)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), fi.Mode().Perm())
}

func TestInstallRootOwnedCodeServer_RemovesThePrefixWhenTheInstallFails(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "code-server")
	install := func() error {
		if err := os.MkdirAll(filepath.Join(prefix, "lib"), 0755); err != nil {
			return err
		}
		return errors.New("install script failed")
	}

	err := installRootOwnedCodeServer(prefix, os.Getuid(), os.Getgid(), install)

	assert.ErrorContains(t, err, "install script failed")
	_, statErr := os.Stat(prefix)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestLockCodeServerPrefix_RefusesAGroupWritableParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "alpamon")
	require.NoError(t, os.Mkdir(parent, 0755))
	require.NoError(t, os.Chmod(parent, 0775))
	prefix := filepath.Join(parent, "code-server")

	err := lockCodeServerPrefix(prefix, os.Getuid(), os.Getgid())

	assert.ErrorContains(t, err, "writable by group or other")
	_, statErr := os.Stat(prefix)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestManagedEditorReleasePermissions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned install directory")
	}
	// Use a directory on the same trust boundary as the production install.
	parent, err := os.MkdirTemp("/opt", "alpamon-editor-test-")
	if err != nil {
		t.Skipf("no writable install location: %v", err)
	}
	defer func() { _ = os.RemoveAll(parent) }()
	require.NoError(t, os.Chmod(parent, 0755))
	release := filepath.Join(parent, "release")
	require.NoError(t, prepareEditorReleaseParent(release))
	require.NoError(t, verifyEditorRelease(release))
	nested := filepath.Join(release, "lib")
	require.NoError(t, os.Mkdir(nested, 0755))
	require.NoError(t, os.Chmod(nested, os.ModeSticky|0777))
	require.ErrorContains(t, verifyEditorRelease(release), "only by root")
	stage := filepath.Join(parent, "stage")
	bin := filepath.Join(stage, "bin")
	require.NoError(t, prepareEditorReleaseParent(bin))
	writeEditorRuntimeFixture(t, stage)
	require.Error(t, checkEditorRelease(stage))
	require.NoError(t, publishEditorRelease(stage, release, true))
	require.NoError(t, checkEditorRelease(release))
	require.NoError(t, os.Remove(filepath.Join(release, "lib", "node")))
	assert.ErrorIs(t, checkEditorRelease(release), os.ErrNotExist)
	require.NoError(t, os.MkdirAll(nested, 0755))
	require.NoError(t, os.Chmod(nested, 0777))
	assert.ErrorContains(t, checkEditorRelease(release), "only by root")
	require.NoError(t, os.Chmod(nested, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "node"), nil, 0755))
	require.NoError(t, checkEditorRelease(release))
	require.NoError(t, os.Remove(filepath.Join(release, editorReleaseMarker)))
	assert.ErrorIs(t, checkEditorRelease(release), os.ErrNotExist)
}

func TestLookupCodeServerPathFindsPerUserInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(home, ".local", "bin", "code-server")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, nil, 0755))

	found, err := lookupCodeServerPath("linux", false)
	require.NoError(t, err)
	assert.Equal(t, path, found)
}

func TestLookupCodeServerPathSkipsInvalidPerUserInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(home, ".local", "bin", "code-server")
	system := filepath.Join(t.TempDir(), "code-server")
	require.NoError(t, os.WriteFile(system, nil, 0755))
	saved := codeServerPaths
	codeServerPaths = []string{system}
	t.Cleanup(func() { codeServerPaths = saved })
	require.NoError(t, os.MkdirAll(path, 0755))

	found, err := lookupCodeServerPath("linux", false)
	require.NoError(t, err)
	assert.Equal(t, system, found)

	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, nil, 0644))
	found, err = lookupCodeServerPath("linux", false)
	require.NoError(t, err)
	assert.Equal(t, system, found)
}

func TestCodeServerKeepsInheritedUmask(t *testing.T) {
	if runtime.GOOS == "darwin" && os.Getuid() == 0 {
		t.Skip("root on macOS uses a fixed code-server install")
	}
	home := t.TempDir()
	bin := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin)
	output := filepath.Join(home, "umask")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "code-server"), []byte("#!/bin/sh\numask > umask\n"), 0755))

	want, err := exec.CommandContext(t.Context(), "/bin/sh", "-c", "umask").Output()
	require.NoError(t, err)
	userDataDir, err := setupUserDataDir(t.Context(), home, "", "")
	require.NoError(t, err)
	socketDir := filepath.Join(home, "sockets", "session")
	m := &CodeServerManager{homeDir: home, socketPath: filepath.Join(socketDir, "editor.sock")}
	require.NoError(t, prepareEditorSocketDir(m))
	t.Cleanup(func() { _ = m.socketRoot.Close() })

	cmd, err := startCodeServerProcess(t.Context(), m, userDataDir)
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	for _, dir := range []string{socketDir, userDataDir} {
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), dir)
	}
}
