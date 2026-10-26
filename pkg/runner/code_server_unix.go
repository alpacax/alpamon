//go:build !windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"

	"github.com/rs/zerolog/log"
)

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

	args := getCodeServerArgs(m.port, userDataDir)
	cmd := exec.CommandContext(ctx, codeServerPath, args...)
	cmd.Dir = m.homeDir

	cmd.Env = getCodeServerEnv(m.homeDir, runtime.GOOS != "darwin")
	cmd.SysProcAttr = codeServerSysProcAttr(m.procAttr)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start code-server: %w", err)
	}

	if m.procAttr != nil {
		log.Info().Msgf("code-server process started on port %d (user: %s, group: %s).", m.port, m.username, m.groupname)
	} else {
		log.Info().Msgf("code-server process started on port %d as the current user.", m.port)
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
