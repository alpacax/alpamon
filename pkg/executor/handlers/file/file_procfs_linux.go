package file

import "golang.org/x/sys/unix"

func rootTransferOnProcfs(path string) (bool, error) {
	// Inspect the component itself, including when it is a symbolic link.
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()

	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return false, err
	}
	return fs.Type == unix.PROC_SUPER_MAGIC, nil
}
