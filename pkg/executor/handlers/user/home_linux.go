package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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

func (l *linuxAccountLocker) backupHomeDirectory(ctx context.Context, name string, account *user.User, base, destination string) error {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("archive_refused: invalid account UID: %w", err)
	}
	minUID, maxUID := l.uidBounds()
	if isProtectedAccount(name, uid) || uid < minUID || uid > maxUID {
		return fmt.Errorf("archive_refused: %q has protected or system UID %d", name, uid)
	}
	home := filepath.Clean(account.HomeDir)
	homeRoot := l.handler.homeRoot
	if filepath.Dir(home) != homeRoot || filepath.Base(home) == "deleted_users" {
		return fmt.Errorf("archive_refused: home %q must be a direct child of /home other than deleted_users", home)
	}
	homeFD, err := unix.Open(homeRoot, archiveDirFlags, 0)
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return errors.New("archive_refused: /home must be a real directory, symlinks are refused")
	}
	if err != nil {
		return fmt.Errorf("archive_refused: cannot open /home: %w", err)
	}
	defer func() { _ = unix.Close(homeFD) }()

	// A trusted parent keeps the source name stable against unprivileged users
	// between validation and rename.
	var rootStat unix.Stat_t
	if err := unix.Fstat(homeFD, &rootStat); err != nil {
		return fmt.Errorf("archive_refused: cannot stat /home: %w", err)
	}
	if rootStat.Uid != uint32(os.Geteuid()) || rootStat.Mode&0022 != 0 {
		return errors.New("archive_refused: /home must be root-owned and writable only by root")
	}

	source := filepath.Base(home)
	info, err := os.Lstat(filepath.Join("/proc/self/fd", strconv.Itoa(homeFD), source))
	if err != nil {
		return fmt.Errorf("archive_refused: cannot stat home %s: %w", home, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("archive_refused: home %s is not a real directory", home)
	}
	owner, err := fileOwnerUID(info)
	if err != nil {
		return fmt.Errorf("archive_refused: %w", err)
	}
	if owner != uid {
		return fmt.Errorf("archive_refused: home %s is owned by UID %d, expected UID %d", home, owner, uid)
	}
	if err := l.checkSharedHome(name, home); err != nil {
		return err
	}
	if err := l.checkArchiveActivity(ctx, uid); err != nil {
		return err
	}
	if err := l.checkHomeMounts(home); err != nil {
		return err
	}
	archiveFD, err := l.openArchiveParent(homeFD)
	if err != nil {
		return fmt.Errorf("archive_refused: %w", err)
	}
	defer func() { _ = unix.Close(archiveFD) }()

	if err := l.renameAt(homeFD, source, archiveFD, base, unix.RENAME_NOREPLACE); err != nil {
		return archiveRenameError(destination, err)
	}
	archived := filepath.Join("/proc/self/fd", strconv.Itoa(archiveFD), base)
	skipped, err := l.handler.chownHome(archived, 0, 0, int(uid))
	if err != nil {
		return archivedDeleteFailure(destination, fmt.Errorf("failed to chown archived directory: %w", err))
	}
	if err := os.Chmod(archived, 0700); err != nil {
		return archivedDeleteFailure(destination, fmt.Errorf("failed to chmod archived directory: %w", err))
	}
	log.Info().Str("archiveDir", destination).Int("hardLinksLeftUnchanged", skipped).Msg("Home directory archived")
	return nil
}

func (l *linuxAccountLocker) checkSharedHome(name, home string) error {
	passwd, err := l.readFile("/etc/passwd")
	if err != nil {
		return fmt.Errorf("archive_refused: cannot read passwd entries: %w", err)
	}
	for line := range strings.SplitSeq(string(passwd), "\n") {
		fields := strings.SplitN(line, ":", 7)
		if len(fields) != 7 || fields[0] == name {
			continue
		}
		if path := filepath.Clean(fields[5]); path == home || strings.HasPrefix(path, home+"/") {
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
