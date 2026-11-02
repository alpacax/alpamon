//go:build !windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

var editorSocketSweepOnce = new(sync.Once)
var removeEditorSocketEntry = (*os.Root).RemoveAll
var editorOpenRoot = os.OpenRoot
var editorOpenRootAt = (*os.Root).OpenRoot

// startCodeServerProcess starts code-server in its own process group as m.procAttr's user,
// or as Alpamon's own user when it is nil.
func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "darwin" && os.Getuid() == 0 {
		if err := verifyOwnedPath(codeServerPath, 0); err != nil {
			return nil, fmt.Errorf("refusing to start code-server: %w", err)
		}
	}

	args := getCodeServerArgs(m.socketPath, userDataDir)
	cmd := exec.CommandContext(ctx, codeServerPath, args...)
	cmd.Dir = m.homeDir

	cmd.Env = getCodeServerEnv(m.homeDir, runtime.GOOS != "darwin", m.username)
	cmd.Env = append(cmd.Env, "XDG_RUNTIME_DIR="+filepath.Dir(m.socketPath))
	cmd.SysProcAttr = codeServerSysProcAttr(m.procAttr)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start code-server: %w", err)
	}

	if m.procAttr != nil {
		log.Info().Msgf("code-server process started (user: %s, group: %s).", m.username, m.groupname)
	} else {
		log.Info().Msg("code-server process started as the current user.")
	}

	return cmd, nil
}

// codeServerSysProcAttr returns a copy of procAttr with Setpgid set, leaving the shared one untouched.
func codeServerSysProcAttr(procAttr *syscall.SysProcAttr) *syscall.SysProcAttr {
	attr := syscall.SysProcAttr{}
	if procAttr != nil {
		attr = *procAttr
	}
	attr.Setpgid = true
	return &attr
}

// installRootOwnedCodeServer runs install into prefix while only uid can enter it, gives the tree
// to uid:gid, then opens prefix to every account; on failure it removes prefix so the next start retries.
func installRootOwnedCodeServer(prefix string, uid, gid int, install func() error) error {
	if err := lockCodeServerPrefix(prefix, uid, gid); err != nil {
		return fmt.Errorf("failed to prepare code-server install dir: %w", err)
	}
	err := install()
	if err == nil {
		// macOS tar run as root restores the archive's owner (501:20), handing the tree to the first account.
		if err = secureCodeServerTree(prefix, uid, gid); err != nil {
			err = fmt.Errorf("failed to secure code-server install: %w", err)
		}
	}
	if err == nil {
		if err = os.Chmod(prefix, 0755); err != nil { // demoted users run code-server from it
			err = fmt.Errorf("failed to open code-server install dir: %w", err)
		}
	}
	if err != nil {
		if rmErr := os.RemoveAll(prefix); rmErr != nil {
			log.Error().Err(rmErr).Msgf("failed to remove the incomplete code-server install at %s.", prefix)
		}
		return err
	}
	return nil
}

// lockCodeServerPrefix makes prefix a dir only uid can enter, below parents only root or uid can change.
func lockCodeServerPrefix(prefix string, uid, gid int) error {
	parent := filepath.Dir(prefix)
	if err := mkdirAllOpen(parent); err != nil {
		return err
	}
	if err := verifyOwnedPath(parent, 0, uint32(uid)); err != nil {
		return err
	}
	if err := os.Mkdir(prefix, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(prefix)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", prefix)
	}
	if err := os.Lchown(prefix, uid, gid); err != nil {
		return err
	}
	return os.Chmod(prefix, 0700)
}

// mkdirAllOpen is MkdirAll that sets 0755 on every dir it creates, whatever the umask.
func mkdirAllOpen(dir string) error {
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := mkdirAllOpen(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return err
	}
	return os.Chmod(dir, 0755) // umask must not shut demoted users out
}

// secureCodeServerTree gives every entry under root to uid:gid and drops group and other write.
// Each dir is secured before its entries, so no other account can swap one mid-walk.
func secureCodeServerTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0022 == 0 {
			return nil
		}
		return os.Chmod(path, info.Mode()&^0022)
	})
}

// verifyOwnedPath refuses path when it, its symlink target, or a dir above either is owned outside
// allowedOwners or writable by group or other (sticky dirs excepted); files path loads go unchecked.
func verifyOwnedPath(path string, allowedOwners ...uint32) error {
	for _, p := range []string{filepath.Dir(path), path} {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return err
		}
		for dir := resolved; ; dir = filepath.Dir(dir) {
			if err := verifyOwnedEntry(dir, allowedOwners); err != nil {
				return err
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
	}
	return nil
}

func verifyOwnedEntry(path string, allowedOwners []uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if !slices.Contains(allowedOwners, st.Uid) {
		return fmt.Errorf("%s is owned by uid %d, which is not allowed", path, st.Uid)
	}
	if info.Mode().Perm()&0022 != 0 && (!info.IsDir() || info.Mode()&fs.ModeSticky == 0) {
		return fmt.Errorf("%s is writable by group or other", path)
	}
	return nil
}

func prepareEditorSocketDir(m *CodeServerManager) error {
	uid, gid := os.Geteuid(), os.Getegid()
	if m.procAttr != nil && m.procAttr.Credential != nil {
		uid, gid = int(m.procAttr.Credential.Uid), int(m.procAttr.Credential.Gid)
	}
	dir := filepath.Dir(m.socketPath)
	base := filepath.Dir(dir)
	var root *os.Root
	var err error
	if os.Geteuid() != 0 {
		parent, openErr := openEditorDirectory(filepath.Dir(base))
		if openErr != nil {
			return fmt.Errorf("editor RunDir: %w", openErr)
		}
		defer func() { _ = parent.Close() }()
		if err := validateEditorRunDir(parent, uint32(os.Geteuid())); err != nil {
			return err
		}
		root, err = openEditorSocketBaseAt(parent, filepath.Base(base))
	} else {
		root, err = openEditorSocketBase(base)
	}
	if err != nil {
		return err
	}
	m.socketRoot = root
	if err := createEditorSessionDirAt(root, filepath.Base(dir), uid, gid, root.Lchown); err != nil {
		_ = root.Close()
		m.socketRoot = nil
		return err
	}
	return nil
}

// openEditorDirectory pins a directory without following its final component.
func openEditorDirectory(path string) (*os.Root, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	root, err := editorOpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("editor directory changed while opening")
	}
	return root, nil
}

func openEditorSocketBaseAt(parent *os.Root, name string) (*os.Root, error) {
	if err := parent.Mkdir(name, 0711); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	dir, err := parent.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	root, err := editorOpenRootAt(parent, name)
	if err != nil {
		return nil, err
	}
	pinned, statErr := file.Stat()
	opened, openErr := root.Stat(".")
	if statErr != nil || openErr != nil || !os.SameFile(pinned, opened) {
		_ = root.Close()
		return nil, fmt.Errorf("editor socket base changed while opening")
	}
	if err := checkEditorSocketBase(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func openEditorSocketBase(base string) (*os.Root, error) {
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(base))
	if err != nil {
		return nil, err
	}
	parent, err := openEditorDirectory(parentPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	return openEditorSocketBaseAt(parent, filepath.Base(base))
}

func checkEditorSocketBase(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("editor socket base must be an agent-owned directory")
	}
	if err := file.Chmod(0711); err != nil {
		return err
	}
	editorSocketSweepOnce.Do(func() { sweepEditorSocketRoot(root) })
	return nil
}

func createEditorSessionDirAt(root *os.Root, name string, uid, gid int, chown func(string, int, int) error) error {
	if err := root.RemoveAll(name); err != nil {
		return err
	}
	if err := root.Mkdir(name, 0700); err != nil {
		return err
	}
	file, err := root.Open(name)
	if err == nil {
		err = file.Chmod(0700)
		_ = file.Close()
	}
	if err == nil {
		err = chown(name, uid, gid)
	}
	if err != nil {
		_ = root.RemoveAll(name)
	}
	return err
}

// Confirm the listener belongs to the editor user.
func validateEditorPeer(conn *net.UnixConn, attr *syscall.SysProcAttr) error {
	expectedUID := uint32(os.Geteuid())
	if attr != nil && attr.Credential != nil {
		expectedUID = attr.Credential.Uid
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var peerUID uint32
	var peerErr error
	if err := raw.Control(func(fd uintptr) { peerUID, peerErr = editorPeerUID(int(fd)) }); err != nil {
		return err
	}
	if peerErr != nil {
		return fmt.Errorf("read editor socket peer: %w", peerErr)
	}
	if peerUID != expectedUID {
		return fmt.Errorf("editor socket peer uid %d differs from editor uid %d", peerUID, expectedUID)
	}
	return nil
}

func sweepEditorSocketRoot(root *os.Root) {
	file, err := root.Open(".")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to open editor socket base for sweep.")
		return
	}
	defer func() { _ = file.Close() }()
	entries, err := file.ReadDir(-1)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read editor socket base for sweep.")
	}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil && info.IsDir() {
			err = removeEditorSocketEntry(root, entry.Name())
		}
		if err != nil {
			log.Warn().Err(err).Str("entry", entry.Name()).Msg("Failed to sweep editor session directory.")
		}
	}
}

func validateEditorRunDir(parent *os.Root, euid uint32) error {
	info, err := parent.Stat(".")
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || (st.Uid != 0 && st.Uid != euid) || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("editor RunDir must be owned by the agent or root and not writable by group or other")
	}
	return nil
}
