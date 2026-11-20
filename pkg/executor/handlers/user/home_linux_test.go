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
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func newHomeTestHandler(t *testing.T, platform string) (*UserHandler, *common.MockCommandExecutor) {
	t.Helper()
	previous := utils.PlatformLike
	utils.PlatformLike = platform
	t.Cleanup(func() { utils.PlatformLike = previous })
	executor := common.NewMockCommandExecutor(t)
	h := NewUserHandler(executor, &MockGroupService{}, nil)
	h.lookupUser = common.AbsentUserLookup
	h.homeRoot = t.TempDir()
	locker := h.accountLocker.(*linuxAccountLocker)
	locker.archiveUID, locker.archiveGID = os.Geteuid(), os.Getegid()
	locker.readFile = func(string) ([]byte, error) { return nil, nil }
	locker.systemd = func() bool { return false }
	locker.scanProcesses = func(uint64, map[int]accountProcess) ([]accountProcess, error) { return nil, nil }
	return h, executor
}

func setArchiveTestAccount(t *testing.T, h *UserHandler, home string) uint64 {
	t.Helper()
	uid := uint64(os.Geteuid())
	if uid == 0 {
		uid = 1001
	}
	if info, err := os.Lstat(home); err == nil && info.IsDir() && os.Geteuid() == 0 {
		require.NoError(t, os.Chown(home, int(uid), -1))
	}
	h.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: strconv.FormatUint(uid, 10), HomeDir: home}, nil
	}
	return uid
}

func TestDeleteHomeDisposition(t *testing.T) {
	const archiveTo = archivePrefix + "alice_2026-11-20T01:02:03Z"
	archive, keep := "archive", "keep"
	for _, tc := range []struct {
		name, platform string
		home           *string
		dest           string
		legacy, absent bool
	}{
		{name: "default keep", platform: "debian"},
		{name: "explicit keep", platform: "rhel", home: &keep, dest: "ignored", legacy: true},
		{name: "archive passwd home", platform: "rhel", home: &archive, dest: archiveTo, legacy: true},
		{name: "missing passwd home", platform: "debian", home: &archive, dest: archiveTo, absent: true},
		{name: "legacy purge archives", platform: "debian", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, tc.platform)
			home := filepath.Join(h.homeRoot, "custom-home")
			if !tc.absent {
				require.NoError(t, os.Mkdir(home, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(home, "file"), []byte("saved"), 0600))
			}
			owner := setArchiveTestAccount(t, h, home)
			var chowned []string
			h.chownHome = func(path string, uid, gid, linkOwner int) (int, error) {
				assert.Equal(t, 0, uid)
				assert.Equal(t, 0, gid)
				assert.Equal(t, int(owner), linkOwner)
				resolved, err := filepath.EvalSymlinks(path)
				require.NoError(t, err)
				chowned = append(chowned, resolved)
				assert.Empty(t, commandArgv(executor), "archive ownership must be set before deletion")
				return 0, nil
			}
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: tc.home, ArchiveTo: tc.dest, PurgeHomeDirectory: tc.legacy,
			})
			require.NoError(t, err)
			if tc.absent {
				assert.Equal(t, 1, code)
				assert.True(t, strings.HasPrefix(output, "archive_refused:"), output)
				assert.Empty(t, commandArgv(executor))
				assert.Empty(t, chowned)
				return
			}
			require.Zero(t, code, output)
			assert.Equal(t, [][]string{{"/usr/sbin/userdel", "alice"}}, commandArgv(executor))
			parent := filepath.Join(h.homeRoot, "deleted_users")
			switch {
			case tc.home == nil && !tc.legacy || tc.home != nil && *tc.home == keep:
				assert.Equal(t, "User 'alice' deleted; home directory kept at "+home, output)
				assert.FileExists(t, filepath.Join(home, "file"))
				assert.Empty(t, chowned)
			default:
				require.Len(t, chowned, 1)
				archived := chowned[0]
				name := filepath.Base(archived)
				want := "User 'alice' deleted; home directory archived to " + archivePrefix + name
				if tc.home == nil && tc.legacy {
					stamp, found := strings.CutPrefix(name, "alice_")
					require.True(t, found)
					when, err := time.Parse(time.RFC3339, stamp)
					require.NoError(t, err)
					assert.True(t, strings.HasSuffix(stamp, "Z"))
					assert.WithinDuration(t, time.Now(), when, 5*time.Second)
					want += " (legacy purge_home=true treated as archive)"
				} else {
					assert.Equal(t, filepath.Base(archiveTo), name)
				}
				assert.Equal(t, want, output)
				_, err := os.Stat(home)
				assert.ErrorIs(t, err, os.ErrNotExist)
				content, err := os.ReadFile(filepath.Join(archived, "file"))
				require.NoError(t, err)
				assert.Equal(t, "saved", string(content))
				for _, path := range []string{parent, archived} {
					info, err := os.Stat(path)
					require.NoError(t, err)
					assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
				}
			}
		})
	}
}

func TestDeleteRejectsInvalidArchivePath(t *testing.T) {
	const valid = archivePrefix + "alice_2026-11-20T01:02:03Z"
	archive := "archive"
	for name, path := range map[string]string{
		"missing": "", "relative": filepath.Base(valid),
		"traversal":            archivePrefix + "../deleted_users/" + filepath.Base(valid),
		"other username":       archivePrefix + "bob_2026-11-20T01:02:03Z",
		"offset":               archivePrefix + "alice_2026-11-20T01:02:03+00:00",
		"invalid date":         archivePrefix + "alice_2026-02-31T01:02:03Z",
		"existing destination": valid,
		"dangling symlink":     valid,
	} {
		t.Run(name, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0700))
			setArchiveTestAccount(t, h, home)
			if path == valid {
				parent := filepath.Join(h.homeRoot, "deleted_users")
				require.NoError(t, os.Mkdir(parent, 0700))
				target := filepath.Join(parent, filepath.Base(valid))
				if name == "dangling symlink" {
					require.NoError(t, os.Symlink(filepath.Join(parent, "missing"), target))
				} else {
					require.NoError(t, os.Mkdir(target, 0700))
				}
			}
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "alice", Home: &archive, ArchiveTo: path})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.True(t, strings.HasPrefix(output, "invalid_archive_path:"), output)
			assert.Empty(t, commandArgv(executor))
			assert.DirExists(t, home)
		})
	}
}

func TestFirstAddUserHomeOwnership(t *testing.T) {
	for _, platform := range []string{"debian", "rhel"} {
		for _, state := range []string{"another UID", "same UID", "missing", "symlink", "dangling symlink", "custom home"} {
			t.Run(platform+"/"+state, func(t *testing.T) {
				h, executor := newHomeTestHandler(t, platform)
				uid := uint64(os.Getuid())
				if uid == 0 {
					uid = 1001
				}
				path := filepath.Join(h.homeRoot, "alice")
				var custom string
				switch state {
				case "symlink":
					require.NoError(t, os.Symlink(t.TempDir(), path))
				case "dangling symlink":
					require.NoError(t, os.Symlink(filepath.Join(h.homeRoot, "missing"), path))
				case "custom home":
					path = filepath.Join(t.TempDir(), "custom-home")
					custom = filepath.Dir(path) + "/./" + filepath.Base(path)
					fallthrough
				case "another UID", "same UID":
					require.NoError(t, os.Mkdir(path, 0755))
					if os.Getuid() == 0 {
						require.NoError(t, os.Chown(path, int(uid), os.Getgid()))
					}
				}
				requested := uid
				if state != "same UID" {
					requested++
				}
				args := &common.CommandArgs{
					Username: "alice", UID: requested, GID: 1001, HomeDirectory: custom,
					Shell: "/bin/bash", Groupname: "alice", Comment: "Alice",
				}
				code, output, err := h.Execute(context.Background(), "adduser", args)
				require.NoError(t, err)
				if strings.HasSuffix(state, "symlink") {
					assert.Equal(t, 1, code)
					assert.Equal(t, "system_home_conflict: "+path+" is a symlink; refusing to create the account", output)
					assert.Empty(t, commandArgv(executor))
					return
				}
				if state == "another UID" || state == "custom home" {
					assert.Equal(t, 1, code)
					assert.Equal(t, fmt.Sprintf("system_home_conflict: %s is owned by uid %d, not %d; refusing to create the account", path, uid, requested), output)
					assert.Empty(t, commandArgv(executor))
					return
				}
				require.Zero(t, code, output)
				tool := "/usr/sbin/adduser"
				if platform == "rhel" {
					tool = "/usr/sbin/useradd"
				}
				calls := commandArgv(executor)
				var creation []string
				for _, argv := range calls {
					if argv[0] == tool {
						creation = argv
					}
				}
				assert.Contains(t, strings.Join(creation, " "), "--uid "+strconv.FormatUint(requested, 10))
			})
		}
	}
}

func TestArchiveRefusesUnsafeHome(t *testing.T) {
	const destination = archivePrefix + "alice_2026-11-20T01:02:03Z"
	archive := "archive"
	for _, tc := range []struct{ state, reason string }{
		{"symlink", "not a real directory"},
		{"file", "not a real directory"},
		{"outside", "must be a direct child"},
		{"nested", "must be a direct child"},
		{"reserved", "must be a direct child"},
		{"wrong owner", "expected UID"},
		{"shared", "also used by"},
		{"system", "protected or system UID"},
		{"protected", "protected or system UID"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			l := h.accountLocker.(*linuxAccountLocker)
			home := filepath.Join(h.homeRoot, "alice")
			switch tc.state {
			case "symlink":
				require.NoError(t, os.Symlink(t.TempDir(), home))
			case "file":
				require.NoError(t, os.WriteFile(home, nil, 0600))
			default:
				switch tc.state {
				case "outside":
					home = filepath.Join(t.TempDir(), "alice")
				case "nested":
					home = filepath.Join(home, "nested")
				case "reserved":
					home = filepath.Join(h.homeRoot, "deleted_users")
				}
				require.NoError(t, os.MkdirAll(home, 0700))
			}
			uid := setArchiveTestAccount(t, h, home)
			name := "alice"
			switch tc.state {
			case "wrong owner":
				uid++
			case "system":
				uid = 999
			case "protected":
				name = "nobody"
			case "shared":
				l.readFile = func(path string) ([]byte, error) {
					if path == "/etc/passwd" {
						return fmt.Appendf(nil, "bob:x:1234:1234::%s/./:/bin/sh\n", home), nil
					}
					return nil, nil
				}
			}
			h.lookupUser = func(string) (*user.User, error) {
				return &user.User{Username: name, Uid: strconv.FormatUint(uid, 10), HomeDir: home}, nil
			}
			before, err := os.Lstat(home)
			require.NoError(t, err)
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: name, Home: &archive, ArchiveTo: strings.Replace(destination, "alice_", name+"_", 1),
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.True(t, strings.HasPrefix(output, "archive_refused:"), output)
			assert.Contains(t, output, tc.reason)
			assert.Empty(t, commandArgv(executor))
			after, err := os.Lstat(home)
			require.NoError(t, err)
			assert.True(t, os.SameFile(before, after))
			assert.Equal(t, before.Mode(), after.Mode())
		})
	}
}

func TestArchiveRefusesUnsafeParent(t *testing.T) {
	const destination = archivePrefix + "alice_2026-11-20T01:02:03Z"
	archive := "archive"
	for _, state := range []string{"symlink", "0755", "non-root owner"} {
		t.Run(state, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "rhel")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0700))
			setArchiveTestAccount(t, h, home)
			parent := filepath.Join(h.homeRoot, "deleted_users")
			switch state {
			case "symlink":
				require.NoError(t, os.Symlink(t.TempDir(), parent))
			case "0755":
				require.NoError(t, os.Mkdir(parent, 0755))
			case "non-root owner":
				require.NoError(t, os.Mkdir(parent, 0700))
				if os.Geteuid() == 0 {
					require.NoError(t, os.Chown(parent, 1001, -1))
				}
				h.accountLocker.(*linuxAccountLocker).archiveUID = 0
			}
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: &archive, ArchiveTo: destination,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.True(t, strings.HasPrefix(output, "archive_refused:"), output)
			assert.Contains(t, output, "archive parent")
			assert.Empty(t, commandArgv(executor))
			assert.DirExists(t, home)
		})
	}
}

func TestArchiveRefusesActiveUser(t *testing.T) {
	for _, activity := range []string{"live processes", "active sessions"} {
		t.Run(activity, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0700))
			uid := setArchiveTestAccount(t, h, home)
			l := h.accountLocker.(*linuxAccountLocker)
			process := &fakeAccountProcess{}
			if activity == "live processes" {
				l.scanProcesses = func(gotUID uint64, _ map[int]accountProcess) ([]accountProcess, error) {
					assert.Equal(t, uid, gotUID)
					return []accountProcess{process}, nil
				}
			} else {
				tool := filepath.Join(t.TempDir(), "loginctl")
				require.NoError(t, os.WriteFile(tool, nil, 0700))
				l.systemd = func() bool { return true }
				l.stat = func(string) (os.FileInfo, error) { return os.Stat(tool) }
				executor.SetResult("/usr/bin/loginctl list-users --no-legend --no-pager", 0, fmt.Sprintf("%d alice\n", uid), nil)
			}

			archive := "archive"
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: &archive, ArchiveTo: archivePrefix + "alice_2026-11-20T01:02:03Z",
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, fmt.Sprintf("user_in_use: UID %d has %s", uid, activity), output)
			if activity == "live processes" {
				assert.True(t, process.closed)
				assert.Empty(t, commandArgv(executor))
			} else {
				assert.Equal(t, [][]string{{"/usr/bin/loginctl", "list-users", "--no-legend", "--no-pager"}}, commandArgv(executor))
			}
			assert.DirExists(t, home)
			_, err = os.Lstat(filepath.Join(h.homeRoot, "deleted_users"))
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestArchiveReportsDeleteFailureWithPath(t *testing.T) {
	const destination = archivePrefix + "alice_2026-11-20T01:02:03Z"
	for _, fail := range []string{"chown", "userdel"} {
		t.Run(fail, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0755))
			uid := setArchiveTestAccount(t, h, home)
			h.chownHome = func(path string, owner, group, linkOwner int) (int, error) {
				assert.Equal(t, filepath.Base(destination), filepath.Base(path))
				assert.Equal(t, 0, owner)
				assert.Equal(t, 0, group)
				assert.Equal(t, int(uid), linkOwner)
				if fail == "chown" {
					return 0, errors.New("ownership failed")
				}
				return 0, nil
			}
			executor.SetResult("/usr/sbin/userdel alice", 8, "account still active", nil)

			archive := "archive"
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: &archive, ArchiveTo: destination,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.True(t, strings.HasPrefix(output, "account_delete_failed: home archived to "+destination+"; "), output)
			assert.Contains(t, output, fail)
			assert.DirExists(t, filepath.Join(h.homeRoot, "deleted_users", filepath.Base(destination)))
			_, err = os.Lstat(home)
			assert.ErrorIs(t, err, os.ErrNotExist)
			if fail == "chown" {
				assert.Empty(t, commandArgv(executor))
			} else {
				assert.Equal(t, [][]string{{"/usr/sbin/userdel", "alice"}}, commandArgv(executor))
			}
		})
	}
}

func TestArchiveRenameRefusals(t *testing.T) {
	const destination = archivePrefix + "alice_2026-11-20T01:02:03Z"
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{unix.ENOSYS, "kernel is too old"},
		{unix.EINVAL, "filesystem does not support atomic no-replace rename"},
		{unix.EXDEV, "different filesystems"},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0700))
			setArchiveTestAccount(t, h, home)
			h.accountLocker.(*linuxAccountLocker).renameAt = func(srcFD int, src string, destFD int, dest string, flags uint) error {
				assert.NotEqual(t, unix.AT_FDCWD, srcFD)
				assert.NotEqual(t, unix.AT_FDCWD, destFD)
				assert.Equal(t, "alice", src)
				assert.Equal(t, filepath.Base(destination), dest)
				assert.Equal(t, uint(unix.RENAME_NOREPLACE), flags)
				return tc.err
			}
			archive := "archive"
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: &archive, ArchiveTo: destination,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.True(t, strings.HasPrefix(output, "archive_refused:"), output)
			assert.Contains(t, output, tc.reason)
			assert.Empty(t, commandArgv(executor))
			assert.DirExists(t, home)
		})
	}
}
