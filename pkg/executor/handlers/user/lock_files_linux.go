package user

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const lockDropInName = "zz-alpamon-user-lock.conf"
const oldLockDropInName = "50-alpamon-user-lock.conf"

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
		if err == nil && len(strings.Split(rel, string(os.PathSeparator))) == 2 && (filepath.Base(path) == lockDropInName || filepath.Base(path) == oldLockDropInName) && strings.HasSuffix(filepath.Dir(rel), ".d") {
			if err := f.remove(path, 0755); err != nil {
				return err
			}
			fd, err := f.directory(root, false, 0755)
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()
			err = unix.Unlinkat(fd, filepath.Dir(rel), unix.AT_REMOVEDIR)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTEMPTY) {
				return nil
			}
			return err
		}
	}
	return fmt.Errorf("invalid drop-in path: %s", path)
}

func validService(unit string) bool {
	return strings.HasSuffix(unit, ".service") && !strings.HasPrefix(unit, "-") && !strings.ContainsAny(unit, "/\x00\r\n\t ")
}

func lockDropInPaths(paths []string) []string {
	var result []string
	for _, path := range paths {
		candidates := []string{path}
		if base := filepath.Base(path); base == lockDropInName || base == oldLockDropInName {
			candidates = []string{filepath.Join(filepath.Dir(path), oldLockDropInName), filepath.Join(filepath.Dir(path), lockDropInName)}
		}
		for _, candidate := range candidates {
			if !slices.Contains(result, candidate) {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (f lockFiles) findDropIns(name string) ([]string, error) {
	var paths []string
	condition := "!" + filepath.Join(f.markerDir, name)
	for _, root := range f.unitDirs {
		fd, err := f.directory(root, false, 0755)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		dir := os.NewFile(uintptr(fd), root)
		entries, readErr := dir.ReadDir(-1)
		closeErr := dir.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".d") {
				continue
			}
			for _, base := range []string{oldLockDropInName, lockDropInName} {
				path := filepath.Join(root, entry.Name(), base)
				matches, err := f.dropInNamesMarker(path, condition)
				if err != nil {
					return nil, err
				}
				if matches {
					paths = append(paths, path)
				}
			}
		}
	}
	return paths, nil
}

func (f lockFiles) dropInNamesMarker(path, condition string) (bool, error) {
	fd, err := f.directory(filepath.Dir(path), false, 0755)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	fileFD, err := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fileFD), path)
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != f.owner || stat.Mode&0022 != 0 {
		return false, fmt.Errorf("unsafe lock drop-in: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, 1024*1024))
	if err != nil {
		return false, err
	}
	section := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section == "[Unit]" && strings.TrimSpace(key) == "ConditionPathExists" && strings.TrimSpace(value) == condition {
			return true, nil
		}
	}
	return false, nil
}
