package user

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const lockDropInName = "50-alpamon-user-lock.conf"

type lockFiles struct {
	markerDir string
	unitDirs  []string
	owner     uint32
}

// Pin each directory component so neither a parent nor the final directory can
// redirect a privileged write through a symlink.
func (f lockFiles) directory(path string, create bool, mode uint32) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("invalid lock directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		perm := uint32(0755)
		if i == len(parts)-1 {
			perm = mode
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err = unix.Mkdirat(fd, part, perm); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, err
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil && (st.Uid != f.owner || st.Mode&0022 != 0 || (mode == 0700 && st.Mode&0777 != mode)) {
		err = fmt.Errorf("lock directory must be root-owned with safe permissions")
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (f lockFiles) write(path, content string, mode, dirMode uint32) error {
	fd, err := f.directory(filepath.Dir(path), true, dirMode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	temp := ".alpamon-lock-" + rand.Text()
	fileFD, err := unix.Openat(fd, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(fd, temp, 0) }()
	file := os.NewFile(uintptr(fileFD), temp)
	defer func() { _ = file.Close() }()
	if err = file.Chown(int(f.owner), -1); err != nil {
		return err
	}
	if err = file.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if _, err = file.WriteString(content); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(fd, temp, fd, filepath.Base(path)); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func (f lockFiles) marker(name string, create bool) error {
	if err := validateLockUserName(name); err != nil {
		return err
	}
	path := filepath.Join(f.markerDir, name)
	if create {
		return f.write(path, "", 0600, 0700)
	}
	return f.remove(path, 0700)
}

func (f lockFiles) remove(path string, mode uint32) error {
	fd, err := f.directory(filepath.Dir(path), false, mode)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	err = unix.Unlinkat(fd, filepath.Base(path), 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func (f lockFiles) removeDropIn(path string) error {
	for _, root := range f.unitDirs {
		rel, err := filepath.Rel(root, path)
		if err == nil && len(strings.Split(rel, string(os.PathSeparator))) == 2 && filepath.Base(path) == lockDropInName && validService(strings.TrimSuffix(filepath.Dir(rel), ".d")) {
			return f.remove(path, 0755)
		}
	}
	return fmt.Errorf("invalid drop-in path: %s", path)
}

func validService(unit string) bool {
	return strings.HasSuffix(unit, ".service") && !strings.HasPrefix(unit, "-") && !strings.ContainsAny(unit, "/\x00\r\n\t ")
}
