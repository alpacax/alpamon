//go:build !windows

package runner

import (
	"cmp"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// The user owns the home directory, so any path under it can be swapped for a
// symlink between a check and the use of the checked path. Every operation
// below the home directory therefore resolves one path component at a time
// against a held directory fd with O_NOFOLLOW, which leaves no window to
// redirect root's writes or chowns elsewhere. The home directory itself is
// opened by full path, and every name handed to these helpers must be a single
// component: O_NOFOLLOW guards only the last one, so a separator inside a name
// would let the components before it be followed.

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// The home directory's own entry sits in a directory the user does not own, so
// nothing there is theirs to swap and following a link is safe. Admins do point
// home directories at another filesystem that way, and refusing them would turn
// a supported layout into an editor that will not start.
const homeDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC

// The walk holds one directory fd per level, and the tree below the user data
// dir is whatever the user puts there. alpamon.service sets no LimitNOFILE, so
// the systemd default applies to the whole agent: a deep enough chain would
// starve the WebSocket connection and the FTP sessions of descriptors. Nothing
// code-server writes comes close to this depth.
const maxChownDepth = 64

// A temp file only outlives writeFileAt when the process dies between the
// create and the rename, and the age cut keeps a sweep away from one another
// session is filling right now.
const staleTempAge = time.Hour

// A temp file is named for the file it will become, so a sweep can tell one
// apart from whatever else the user keeps in the directory.
const tempSuffix = ".tmp"

func tempPrefix(name string) string { return "." + name + "." }

// setupUserDataFiles creates dirName/User under homeDir and writes config.yaml
// and User/settings.json, refusing to traverse or write through symlinks.
func setupUserDataFiles(homeDir, dirName string, configData, settingsData []byte) error {
	home, err := openDir(homeDir, homeDirFlags)
	if err != nil {
		return err
	}
	defer func() { _ = home.Close() }()

	dataDir, err := mkdirOpenAt(home, dirName)
	if err != nil {
		return err
	}
	defer func() { _ = dataDir.Close() }()

	userDir, err := mkdirOpenAt(dataDir, userDataUserDir)
	if err != nil {
		return err
	}
	defer func() { _ = userDir.Close() }()

	sweepStaleTemps(dataDir, userDataConfigFile)
	sweepStaleTemps(userDir, userDataSettingsFile)

	if err := writeFileAt(dataDir, userDataConfigFile, configData); err != nil {
		return err
	}
	return writeFileAt(userDir, userDataSettingsFile, settingsData)
}

// chownTreeNoFollow recursively changes ownership under root without ever
// following a symlink: links themselves are re-owned, their targets untouched.
func chownTreeNoFollow(root string, uid, gid int) error {
	dir, err := openDir(root, dirFlags)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()

	if err := dir.Chown(uid, gid); err != nil {
		return err
	}
	return chownChildren(dir, uid, gid, maxChownDepth)
}

func chownChildren(dir *os.File, uid, gid, depth int) error {
	if depth <= 0 {
		return fmt.Errorf("user data dir nests deeper than %d levels at %s", maxChownDepth, dir.Name())
	}

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	dirfd := int(dir.Fd())
	for _, name := range names {
		// Stat before the chown, not after: AT_SYMLINK_NOFOLLOW speaks only for
		// symlinks, and a hard link is not a link to a file but a second name
		// for the same inode, one the user can plant pointing anywhere they can
		// read. Handing that inode away is exactly what this walk must not do.
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return &os.PathError{Op: "stat", Path: filepath.Join(dir.Name(), name), Err: err}
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink > 1 {
			continue
		}
		if err := unix.Fchownat(dirfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return &os.PathError{Op: "lchown", Path: filepath.Join(dir.Name(), name), Err: err}
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		path := filepath.Join(dir.Name(), name)
		childFd, err := unix.Openat(dirfd, name, dirFlags, 0)
		if err != nil {
			return &os.PathError{Op: "open", Path: path, Err: err}
		}
		child := os.NewFile(uintptr(childFd), path)
		err = chownChildren(child, uid, gid, depth-1)
		_ = child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// openDir opens path as a directory fd. Under dirFlags the final component must
// not be a symlink; homeDirFlags drops that and is only for the home directory.
func openDir(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// mkdirOpenAt creates name under parent if missing and opens it. A symlink or
// regular file squatting on the name fails the open (ELOOP or ENOTDIR).
func mkdirOpenAt(parent *os.File, name string) (*os.File, error) {
	path := filepath.Join(parent.Name(), name)
	if err := unix.Mkdirat(int(parent.Fd()), name, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	fd, err := unix.Openat(int(parent.Fd()), name, dirFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// sweepStaleTemps removes the temp files a writeFileAt of name left behind by
// dying before its rename. Nothing else collects them, and the directory
// belongs to the user, so they would sit there for the life of the account.
// A failure here is not worth refusing to start the editor over.
func sweepStaleTemps(parent *os.File, name string) {
	names, err := parent.Readdirnames(-1)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to list %s while sweeping temp files.", parent.Name())
		return
	}

	dirfd := int(parent.Fd())
	prefix, cutoff := tempPrefix(name), time.Now().Add(-staleTempAge)
	for _, entry := range names {
		if !strings.HasPrefix(entry, prefix) || !strings.HasSuffix(entry, tempSuffix) {
			continue
		}
		// Stat through an fd rather than the name, so the age that decides the
		// unlink is read off the very entry the name resolved to. O_NONBLOCK
		// because the temp name is predictable and mkfifo needs no privilege:
		// a FIFO parked here would hold this open until a writer arrived, and
		// the IsRegular check that rejects it comes after the open.
		fd, err := unix.Openat(dirfd, entry,
			unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		f := os.NewFile(uintptr(fd), entry)
		info, err := f.Stat()
		_ = f.Close()
		if err != nil || !info.Mode().IsRegular() || info.ModTime().After(cutoff) {
			continue
		}
		_ = unix.Unlinkat(dirfd, entry, 0)
	}
}

// writeFileAt replaces name under parent, refusing to write through a symlink.
// The bytes land in a sibling temp file that renameat swaps into place, so a
// concurrent reader—a running code-server watches settings.json—gets the old
// file or the new one, never the empty window an O_TRUNC write opens.
func writeFileAt(parent *os.File, name string, data []byte) error {
	dirfd := int(parent.Fd())
	path := filepath.Join(parent.Name(), name)

	// renameat replaces a symlink at name rather than following it, which is
	// safe but silent, so a planted link is reported here instead. The report is
	// all this is: the rename stays inside the tree whatever appears after the
	// check, and stat creates nothing, so a failure below leaves no file behind.
	mode := uint32(0644)
	var st unix.Stat_t
	switch err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == unix.ENOENT:
	case err != nil:
		return &os.PathError{Op: "stat", Path: path, Err: err}
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return &os.PathError{Op: "open", Path: path, Err: unix.ELOOP}
	case st.Mode&unix.S_IFMT == unix.S_IFREG:
		// A replacement takes its mode from this call rather than from the file
		// it lands on, so carry the old one over: an admin who tightened
		// settings.json keeps that on the next start.
		mode = uint32(st.Mode) & 0777
	}

	// Two editor sessions for one user set the directory up concurrently, so the
	// temp name has to be unique per call, not per process.
	tmp := tempPrefix(name) + strconv.FormatUint(rand.Uint64(), 36) + tempSuffix
	tmpPath := filepath.Join(parent.Name(), tmp)
	fd, err := unix.Openat(dirfd, tmp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return &os.PathError{Op: "open", Path: tmpPath, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmpPath)
	// O_CREAT applies the mode as mode &^ umask, which would narrow the mode
	// carried over above; fchmod is not subject to the umask.
	if err := unix.Fchmod(fd, mode); err != nil {
		_ = f.Close()
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return &os.PathError{Op: "chmod", Path: tmpPath, Err: err}
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := cmp.Or(writeErr, closeErr); err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return err
	}

	if err := unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return &os.PathError{Op: "rename", Path: path, Err: err}
	}
	return nil
}
