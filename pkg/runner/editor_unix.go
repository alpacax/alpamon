//go:build !windows

package runner

import (
	"cmp"
	"context"
	"errors"
	"io"
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

// For an entry of unknown type, so that stat and chown act on the descriptor
// rather than on a name the user can rename something else onto in between.
// O_RDONLY on a FIFO would wait for a writer; O_NOFOLLOW makes a symlink ELOOP.
const entryFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

// Reading a user-controlled directory whole would materialize millions of
// strings in the root agent and put the first cancellation check after all of it.
const readdirBatch = 512

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
func setupUserDataFiles(ctx context.Context, homeDir, dirName string, configData, settingsData []byte) error {
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

	sweepStaleTemps(ctx, dataDir, userDataConfigFile)
	sweepStaleTemps(ctx, userDir, userDataSettingsFile)

	if err := writeFileAt(dataDir, userDataConfigFile, configData); err != nil {
		return err
	}
	return writeFileAt(userDir, userDataSettingsFile, settingsData)
}

// eachName calls fn for every entry in dir, a batch at a time, and stops as soon
// as ctx is done: closing the editor session has to end a walk over a directory
// the user made as wide as they liked.
func eachName(ctx context.Context, dir *os.File, fn func(name string) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := dir.Readdirnames(readdirBatch)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(name); err != nil {
				return err
			}
		}
	}
}

// chownTreeNoFollow re-owns the tree under root, holding every entry open before
// acting on it. What it cannot open that way—symlinks, sockets—it leaves alone
// rather than reaching by name.
func chownTreeNoFollow(ctx context.Context, root string, uid, gid int) error {
	dir, err := openDir(root, dirFlags)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := dir.Chown(uid, gid); err != nil {
		return err
	}
	return chownChildren(ctx, dir, uid, gid, maxChownDepth)
}

func chownChildren(ctx context.Context, dir *os.File, uid, gid, depth int) error {
	dirfd := int(dir.Fd())
	return eachName(ctx, dir, func(name string) error {
		path := filepath.Join(dir.Name(), name)
		// An open that fails skips the entry, not the walk: ELOOP is a symlink,
		// ENXIO a socket, ENOENT one a live code-server just removed, and none
		// is worth leaving the settings.json elsewhere in the tree root-owned.
		fd, err := unix.Openat(dirfd, name, entryFlags, 0)
		if err != nil {
			return nil
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return &os.PathError{Op: "stat", Path: path, Err: err}
		}
		isDir := st.Mode&unix.S_IFMT == unix.S_IFDIR
		// A hard link is a second name for one inode, and the user can plant one
		// over anything link() lets them reach. Directories always carry a second
		// name in ".", so the count means this only for the other types.
		if !isDir && st.Nlink > 1 {
			_ = unix.Close(fd)
			return nil
		}
		if err := unix.Fchown(fd, uid, gid); err != nil {
			_ = unix.Close(fd)
			return &os.PathError{Op: "chown", Path: path, Err: err}
		}
		// Skip the subtree, not the walk: the files this run wrote have to change
		// hands whatever the user parked beside them, and readdir order decides
		// which the walk meets first.
		if !isDir || depth <= 0 {
			if isDir {
				log.Warn().Msgf("Not descending past %d levels at %s; ownership below it is left as it is.", maxChownDepth, path)
			}
			_ = unix.Close(fd)
			return nil
		}
		child := os.NewFile(uintptr(fd), path)
		err = chownChildren(ctx, child, uid, gid, depth-1)
		_ = child.Close()
		return err
	})
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
func sweepStaleTemps(ctx context.Context, parent *os.File, name string) {
	dirfd := int(parent.Fd())
	prefix, cutoff := tempPrefix(name), time.Now().Add(-staleTempAge)
	err := eachName(ctx, parent, func(entry string) error {
		if !strings.HasPrefix(entry, prefix) || !strings.HasSuffix(entry, tempSuffix) {
			return nil
		}
		// Through an fd, so the age that decides the unlink is read off the entry
		// the name resolved to and not off whatever replaced it since.
		fd, err := unix.Openat(dirfd, entry, entryFlags, 0)
		if err != nil {
			return nil
		}
		f := os.NewFile(uintptr(fd), entry)
		info, err := f.Stat()
		_ = f.Close()
		if err != nil || !info.Mode().IsRegular() || info.ModTime().After(cutoff) {
			return nil
		}
		_ = unix.Unlinkat(dirfd, entry, 0)
		return nil
	})
	if err != nil {
		log.Debug().Err(err).Msgf("Stopped sweeping temp files under %s.", parent.Name())
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
