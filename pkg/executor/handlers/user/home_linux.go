package user

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

const archiveDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func fileOwnerUID(info os.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to read owner of %s", info.Name())
	}
	return uint64(stat.Uid), nil
}

type pendingArchive struct {
	UID           uint64
	Home, Base    string
	Device, Inode uint64
}

func archiveRecordPath(fd int, name string) string {
	return filepath.Join("/proc/self/fd", strconv.Itoa(fd), fmt.Sprintf(".pending-%x", sha256.Sum256([]byte(name))))
}

func (l *linuxAccountLocker) chooseHomeUID(ctx context.Context, owners map[uint64]string) (uint64, error) {
	minUID, maxUID := l.uidBounds()
	isFree := func(uid uint64) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		_, err := l.lookupUID(strconv.FormatUint(uid, 10))
		var absent user.UnknownUserIdError
		if errors.As(err, &absent) {
			return true, nil
		}
		return false, err
	}
	for uid := range owners {
		if uid == 0 {
			continue
		}
		free, err := isFree(uid)
		if err != nil {
			return 0, fmt.Errorf("failed to check home owner UID %d: %w", uid, err)
		}
		if !free {
			continue
		}
		for candidate := minUID; candidate <= maxUID; candidate++ {
			if _, reserved := owners[candidate]; reserved {
				continue
			}
			available, err := isFree(candidate)
			if err != nil {
				return 0, fmt.Errorf("failed to check available UID %d: %w", candidate, err)
			}
			if available {
				return candidate, nil
			}
		}
		return 0, errors.New("system_home_conflict: no available UID outside retained home ownership")
	}
	return 0, nil
}

func (l *linuxAccountLocker) archiveHome(ctx context.Context, account *user.User, data DeleteUserData) (string, error) {
	name, home := data.Username, filepath.Clean(account.HomeDir)
	var base string
	if !data.LegacyPurge {
		var err error
		base, err = archiveDestination(name, data.ArchiveTo)
		if err != nil {
			return "", err
		}
	}
	uid, err := l.archiveUIDForAccount(name, account)
	if err != nil {
		return "", err
	}
	info, statErr := os.Lstat(home)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("archive_refused: cannot stat home %s: %w", home, statErr)
	}
	homeRoot := l.handler.homeRoot
	if filepath.Dir(home) != homeRoot || filepath.Base(home) == "deleted_users" {
		if statErr != nil {
			return "", nil
		}
		return "", fmt.Errorf("archive_refused: home %q must be a direct child of /home other than deleted_users", home)
	}
	homeFD, err := openArchiveRoot(homeRoot)
	if statErr != nil && errors.Is(err, unix.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(homeFD) }()

	var archiveFD int
	if statErr == nil {
		archiveFD, err = l.openArchiveParent(homeFD)
	} else {
		archiveFD, err = unix.Openat(homeFD, "deleted_users", archiveDirFlags, 0)
		if errors.Is(err, unix.ENOENT) {
			return "", nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("archive_refused: %w", err)
	}
	defer func() { _ = unix.Close(archiveFD) }()
	if err := l.validateArchiveParent(archiveFD, false); err != nil {
		return "", fmt.Errorf("archive_refused: %w", err)
	}

	recordPath := archiveRecordPath(archiveFD, name)
	if statErr != nil {
		record, err := os.ReadFile(recordPath)
		if errors.Is(err, os.ErrNotExist) {
			if base != "" {
				var st unix.Stat_t
				if err := unix.Fstatat(archiveFD, base, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
					return "", archivedDeleteFailure(data.ArchiveTo, errors.New("destination exists or cannot be verified without a pending archive record"))
				}
			}
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("archive_refused: cannot read pending archive: %w", err)
		}
		var pending pendingArchive
		if err := json.Unmarshal(record, &pending); err != nil {
			return "", fmt.Errorf("archive_refused: cannot read pending archive: %w", err)
		}
		destination := archivePrefix + pending.Base
		if _, err := archiveDestination(name, destination); err != nil || pending.UID != uid || pending.Home != home || (base != "" && base != pending.Base) {
			return "", fmt.Errorf("archive_refused: pending archive does not match the request")
		}
		var st unix.Stat_t
		if err := unix.Fstatat(archiveFD, pending.Base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != pending.Device || st.Ino != pending.Inode {
			return "", archivedDeleteFailure(destination, errors.New("pending archive identity could not be verified"))
		}
		if err := l.expireArchiveAccount(ctx, name, uid); err != nil {
			return "", archivedDeleteFailure(destination, err)
		}
		if err := l.checkArchiveActivity(ctx, uid); err != nil {
			return "", archivedDeleteFailure(destination, err)
		}
		return destination, l.finishArchive(ctx, homeFD, archiveFD, pending.Base, destination, uid)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("archive_refused: home %s is not a real directory", home)
	}
	owner, err := fileOwnerUID(info)
	if err != nil {
		return "", fmt.Errorf("archive_refused: %w", err)
	}
	if owner != uid {
		return "", fmt.Errorf("archive_refused: home %s is owned by UID %d, expected UID %d", home, owner, uid)
	}
	if err := l.checkHomeMounts(home); err != nil {
		return "", err
	}
	if err := l.checkSharedHome(ctx, name, home); err != nil {
		return "", err
	}
	if data.LegacyPurge {
		base = name + "_" + time.Now().UTC().Format(time.RFC3339Nano)
	}
	destination := archivePrefix + base
	var target unix.Stat_t
	if err := unix.Fstatat(archiveFD, base, &target, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return "", archiveRenameError(destination, unix.EEXIST)
	} else if !errors.Is(err, unix.ENOENT) {
		return "", fmt.Errorf("archive_refused: cannot check destination: %w", err)
	}
	// Verify that this kernel can enforce the mount boundary before moving the home.
	sourceFD, err := unix.Openat2(homeFD, filepath.Base(home), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return "", fmt.Errorf("archive_refused: cannot open source without crossing a mount: %w", err)
	}
	defer func() { _ = unix.Close(sourceFD) }()
	if err := l.expireArchiveAccount(ctx, name, uid); err != nil {
		return "", err
	}
	if err := l.checkArchiveActivity(ctx, uid); err != nil {
		return "", err
	}
	source := filepath.Base(home)
	var st unix.Stat_t
	if err := unix.Fstat(sourceFD, &st); err != nil {
		return "", fmt.Errorf("archive_refused: cannot verify source: %w", err)
	}
	original, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != uint64(original.Dev) || st.Ino != original.Ino {
		return "", errors.New("archive_refused: home changed before archive")
	}
	record, err := json.Marshal(pendingArchive{UID: uid, Home: home, Base: base, Device: uint64(st.Dev), Inode: st.Ino})
	if err != nil {
		return "", err
	}
	if err := writeArchiveRecord(recordPath, record); err != nil {
		return "", fmt.Errorf("archive_refused: cannot record pending archive: %w", err)
	}
	if err := unix.Fsync(archiveFD); err != nil {
		return "", fmt.Errorf("archive_refused: cannot sync pending archive: %w", err)
	}
	if err := l.renameAt(homeFD, source, archiveFD, base, unix.RENAME_NOREPLACE); err != nil {
		if cleanupErr := os.Remove(recordPath); cleanupErr != nil {
			return "", errors.Join(archiveRenameError(destination, err), cleanupErr)
		}
		return "", archiveRenameError(destination, err)
	}
	return destination, l.finishArchive(ctx, homeFD, archiveFD, base, destination, uid)
}

func writeArchiveRecord(path string, record []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, writeErr := f.Write(record)
	syncErr := f.Sync()
	if err := errors.Join(writeErr, syncErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func openArchiveRoot(path string) (int, error) {
	fd, err := unix.Open(path, archiveDirFlags, 0)
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return -1, errors.New("archive_refused: /home must be a real directory, symlinks are refused")
	}
	if err != nil {
		return -1, fmt.Errorf("archive_refused: cannot open /home: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("archive_refused: cannot stat /home: %w", err)
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("archive_refused: /home must be root-owned and writable only by root")
	}
	return fd, nil
}

func (l *linuxAccountLocker) archiveUIDForAccount(name string, account *user.User) (uint64, error) {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("archive_refused: invalid account UID: %w", err)
	}
	if uid > math.MaxInt {
		return 0, fmt.Errorf("archive_refused: account UID %d cannot be represented as an int", uid)
	}
	minUID, maxUID := l.uidBounds()
	if isProtectedAccount(name, uid) || uid < minUID || uid > maxUID {
		return 0, fmt.Errorf("archive_refused: %q has protected or system UID %d", name, uid)
	}
	return uid, nil
}

func (l *linuxAccountLocker) expireArchiveAccount(ctx context.Context, name string, uid uint64) error {
	if err := l.runForAccount(ctx, name, uid, "/usr/sbin/usermod", "-e", "1", "--", name); err != nil {
		return fmt.Errorf("archive_refused: cannot expire account: %w", err)
	}
	return nil
}

func (l *linuxAccountLocker) finishArchive(ctx context.Context, homeFD, archiveFD int, base, destination string, uid uint64) error {
	if err := errors.Join(unix.Fsync(homeFD), unix.Fsync(archiveFD)); err != nil {
		return archivedDeleteFailure(destination, fmt.Errorf("cannot sync archive move: %w", err))
	}
	fd, err := unix.Openat2(archiveFD, base, &unix.OpenHow{Flags: uint64(archiveDirFlags), Resolve: unix.RESOLVE_NO_XDEV})
	if err != nil {
		return archivedDeleteFailure(destination, err)
	}
	defer func() { _ = unix.Close(fd) }()
	archived := filepath.Join("/proc/self/fd", strconv.Itoa(archiveFD), base)
	if uid > math.MaxInt {
		return archivedDeleteFailure(destination, errors.New("archive UID cannot be represented as an int"))
	}
	skipped, err := l.handler.chownHome(ctx, fd, archived, 0, 0, int(uid))
	if err != nil {
		return archivedDeleteFailure(destination, fmt.Errorf("failed to chown archived directory: %w", err))
	}
	if err := unix.Fchmod(fd, 0700); err != nil {
		return archivedDeleteFailure(destination, fmt.Errorf("failed to chmod archived directory: %w", err))
	}
	log.Info().Str("archiveDir", destination).Int("hardLinksLeftUnchanged", skipped).Msg("Home directory archived")
	return nil
}

func (l *linuxAccountLocker) clearPendingArchive(name string) error {
	homeFD, err := openArchiveRoot(l.handler.homeRoot)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(homeFD) }()
	archiveFD, err := unix.Openat(homeFD, "deleted_users", archiveDirFlags, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(archiveFD) }()
	if err := l.validateArchiveParent(archiveFD, false); err != nil {
		return err
	}
	if err := os.Remove(archiveRecordPath(archiveFD, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return unix.Fsync(archiveFD)
}

// A filesystem may ignore cancellation while resolving a path. Keep at most
// one lookup in flight and let the caller release the account mutation gate.
var sharedHomeLookup = make(chan struct{}, 1)

func (l *linuxAccountLocker) checkSharedHome(ctx context.Context, name, home string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case sharedHomeLookup <- struct{}{}:
	default:
		return errors.New("archive_refused: a previous shared-home lookup is still running")
	}
	result := make(chan error, 1)
	go func() {
		err := l.resolveSharedHome(ctx, name, home)
		<-sharedHomeLookup
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("archive_refused: cannot verify shared homes: %w", ctx.Err())
	}
}

func (l *linuxAccountLocker) resolveSharedHome(ctx context.Context, name, home string) error {
	passwd, err := l.readFile("/etc/passwd")
	if err != nil {
		return fmt.Errorf("archive_refused: cannot read passwd entries: %w", err)
	}
	for line := range strings.SplitSeq(string(passwd), "\n") {
		if err := ctx.Err(); err != nil {
			return err
		}
		fields := strings.SplitN(line, ":", 7)
		if len(fields) != 7 || fields[0] == name {
			continue
		}
		if path := filepath.Clean(fields[5]); path == home || strings.HasPrefix(path, home+"/") {
			return fmt.Errorf("archive_refused: another account's home is inside %s", home)
		}
		if !filepath.IsAbs(fields[5]) {
			continue
		}
		fd, err := unix.Open(fields[5], unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			continue
		}
		if err != nil {
			return fmt.Errorf("archive_refused: cannot resolve home for account %q: %w", fields[0], err)
		}
		resolved, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(fd)))
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("archive_refused: cannot read resolved home for account %q: %w", fields[0], err)
		}
		if resolved == home || strings.HasPrefix(resolved, home+"/") {
			return fmt.Errorf("archive_refused: another account's home is inside %s", home)
		}
	}
	return nil
}

func (l *linuxAccountLocker) checkHomeMounts(home string) error {
	data, err := l.readFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("archive_refused: cannot read mountinfo: %w", err)
	}
	// mountinfo escapes whitespace and backslashes within path fields.
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return errors.New("archive_refused: malformed mountinfo")
		}
		if point := unescape.Replace(fields[4]); point == home || strings.HasPrefix(point, home+"/") {
			return fmt.Errorf("archive_refused: a filesystem is mounted inside %s", home)
		}
	}
	return nil
}

func (l *linuxAccountLocker) checkArchiveActivity(ctx context.Context, uid uint64) error {
	processes, err := l.scanProcesses(uid, nil)
	if err != nil {
		return fmt.Errorf("user_in_use: cannot verify processes for UID %d: %w", uid, err)
	}
	for _, process := range processes {
		process.close()
	}
	if len(processes) > 0 {
		return fmt.Errorf("user_in_use: UID %d has live processes", uid)
	}
	if !l.systemd() {
		return nil
	}
	loginctl, err := l.resolveTool("loginctl")
	if err != nil {
		return fmt.Errorf("user_in_use: cannot verify sessions for UID %d: %w", uid, err)
	}
	active, err := l.hasLoginUser(ctx, loginctl, uid)
	if err != nil {
		return fmt.Errorf("user_in_use: cannot verify sessions for UID %d: %w", uid, err)
	}
	if active {
		return fmt.Errorf("user_in_use: UID %d has active sessions", uid)
	}
	return nil
}

func (l *linuxAccountLocker) hasLoginUser(ctx context.Context, loginctl string, uid uint64) (bool, error) {
	output, err := l.run(ctx, loginctl, "list-users", "--no-legend", "--no-pager")
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		listedUID, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		if listedUID == uid {
			return true, nil
		}
	}
	return false, nil
}

func (l *linuxAccountLocker) openArchiveParent(homeFD int) (int, error) {
	const parent = "deleted_users"
	mkdirErr := unix.Mkdirat(homeFD, parent, 0700)
	if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
		return -1, fmt.Errorf("cannot create archive parent: %w", mkdirErr)
	}
	fd, err := unix.Openat(homeFD, parent, archiveDirFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("cannot open archive parent: %w", err)
	}
	if mkdirErr == nil {
		if err := unix.Fchmod(fd, 0700); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("cannot set archive parent mode: %w", err)
		}
	}
	if err := l.validateArchiveParent(fd, mkdirErr == nil); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (l *linuxAccountLocker) validateArchiveParent(fd int, created bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("cannot stat archive parent: %w", err)
	}
	if stat.Uid != uint32(l.archiveUID) || stat.Mode&07777 != 0700 {
		return errors.New("unsafe archive parent /home/deleted_users: expected a root-owned directory with mode 0700")
	}
	if created && stat.Gid != uint32(l.archiveGID) {
		if err := unix.Fchown(fd, l.archiveUID, l.archiveGID); err != nil {
			return fmt.Errorf("cannot set archive parent ownership: %w", err)
		}
	}
	return nil
}

func archiveRenameError(destination string, err error) error {
	switch {
	case errors.Is(err, unix.EEXIST):
		return fmt.Errorf("invalid_archive_path: %s already exists", destination)
	case errors.Is(err, unix.ENOSYS):
		return fmt.Errorf("archive_refused: kernel is too old for renameat2: %w", err)
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
		return fmt.Errorf("archive_refused: filesystem does not support atomic no-replace rename: %w", err)
	case errors.Is(err, unix.EXDEV):
		return fmt.Errorf("archive_refused: home and archive are on different filesystems: %w", err)
	default:
		return fmt.Errorf("archive_refused: failed to move home directory: %w", err)
	}
}
