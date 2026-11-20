package utils

import (
	"context"
	"os"
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
	return archiveopen.Openat2(fd, name, &unix.OpenHow{
		Flags: uint64(flags), Resolve: unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS,
	})
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
