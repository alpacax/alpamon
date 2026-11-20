package utils

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/v2/internal/archiveopen"
	"golang.org/x/sys/unix"
)

// ChownArchive changes ownership without following symlinks or crossing mounts.
func ChownArchive(ctx context.Context, fd int, path string, uid, gid, linkOwner int) (int, error) {
	walkFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return 0, &os.PathError{Op: "dup", Path: path, Err: err}
	}
	return chownTree(ctx, walkFD, path, uid, gid, linkOwner, true)
}

func openChownChild(fd int, name string, flags int, archive bool) (int, error) {
	if !archive {
		return unix.Openat(fd, name, flags, 0)
	}
	return OpenArchiveEntry(fd, name, flags)
}

// OpenArchiveEntry opens one entry relative to a directory without crossing a mount.
func OpenArchiveEntry(fd int, name string, flags int) (int, error) {
	if name == "" || strings.ContainsRune(name, '/') || flags&unix.O_NOFOLLOW == 0 {
		return -1, unix.EINVAL
	}
	child, err := archiveopen.Openat2(fd, name, &unix.OpenHow{
		Flags: uint64(flags), Resolve: unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS,
	})
	if !errors.Is(err, unix.ENOSYS) {
		return child, err
	}
	return openArchiveEntryFallback(fd, name, flags)
}

func openArchiveEntryFallback(fd int, name string, flags int) (int, error) {
	pinned, err := unix.Openat(fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC|flags&unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(pinned) }()

	parentMount, err := archiveopen.MountID(fd)
	if err != nil {
		return -1, err
	}
	childMount, err := archiveopen.MountID(pinned)
	if err != nil {
		return -1, err
	}
	// Mount IDs distinguish bind mounts that share the parent's device number.
	if parentMount != childMount {
		return -1, unix.EXDEV
	}
	if flags&unix.O_PATH != 0 {
		return unix.FcntlInt(uintptr(pinned), unix.F_DUPFD_CLOEXEC, 0)
	}
	var st unix.Stat_t
	if err := unix.Fstat(pinned, &st); err != nil {
		return -1, err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return -1, unix.ELOOP
	}
	return unix.Open(filepath.Join("/proc/self/fd", strconv.Itoa(pinned)), flags&^unix.O_NOFOLLOW, 0)
}

func statChownChild(fd int, name string, stat *unix.Stat_t, archive bool) error {
	if !archive {
		return unix.Fstatat(fd, name, stat, unix.AT_SYMLINK_NOFOLLOW)
	}
	child, err := openChownChild(fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(child) }()
	return unix.Fstat(child, stat)
}
