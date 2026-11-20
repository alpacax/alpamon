package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/archiveopen"
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
	h.readAccountFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
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
	locker := h.accountLocker.(*linuxAccountLocker)
	readFile := locker.readFile
	locker.readFile = func(path string) ([]byte, error) {
		if path == "/etc/login.defs" {
			return fmt.Appendf(nil, "UID_MIN %d\nUID_MAX %d\n", uid, uid+1), nil
		}
		return readFile(path)
	}
	h.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: strconv.FormatUint(uid, 10), HomeDir: home}, nil
	}
	return uid
}

var deleteAlice = []string{"/usr/sbin/userdel", "alice"}

func TestDeleteHomeDisposition(t *testing.T) {
	const archiveTo = archivePrefix + "alice_2026-11-20T01:02:03Z"
	archive, keep := "archive", "keep"
	for _, tc := range []struct {
		name, platform                  string
		home                            *string
		dest                            string
		legacy, absent, outside, setgid bool
	}{
		{name: "default keep", platform: "debian"},
		{name: "explicit keep", platform: "rhel", home: &keep, dest: "ignored", legacy: true},
		{name: "archive passwd home", platform: "rhel", home: &archive, dest: archiveTo, legacy: true},
		{name: "missing passwd home", platform: "debian", home: &archive, dest: archiveTo, absent: true},
		{name: "missing passwd home outside /home", platform: "debian", home: &archive, dest: archiveTo, absent: true, outside: true},
		{name: "archive with setgid /home", platform: "rhel", home: &archive, dest: archiveTo, setgid: true},
		{name: "legacy purge archives", platform: "debian", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, tc.platform)
			home := filepath.Join(h.homeRoot, "custom-home")
			if tc.outside {
				home = filepath.Join(t.TempDir(), "missing")
			}
			if tc.setgid {
				require.NoError(t, os.Chmod(h.homeRoot, os.ModeSetgid|0700))
			}
			if !tc.absent {
				require.NoError(t, os.Mkdir(home, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(home, "file"), []byte("saved"), 0600))
			}
			owner := setArchiveTestAccount(t, h, home)
			var chowned []string
			h.chownHome = func(_ context.Context, _ int, path string, uid, gid, linkOwner int) (int, error) {
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
			require.Zero(t, code, output)
			if len(chowned) > 0 {
				assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
			} else {
				assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
			}
			if tc.absent {
				assert.Equal(t, "User 'alice' deleted; home directory "+home+" not found; nothing archived", output)
				assert.Empty(t, chowned)
				_, err := os.Lstat(filepath.Join(h.homeRoot, "deleted_users"))
				assert.ErrorIs(t, err, os.ErrNotExist)
				return
			}
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
					assert.Equal(t, os.FileMode(0700), info.Mode()&(os.ModeSetgid|os.ModePerm))
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

func TestInvalidArchivePathWithMissingHomeOrAccount(t *testing.T) {
	archive := "archive"
	for _, state := range []string{"missing home", "missing account"} {
		t.Run(state, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			setArchiveTestAccount(t, h, filepath.Join(h.homeRoot, "alice"))
			if state == "missing account" {
				h.lookupUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
			}
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "alice", Home: &archive, ArchiveTo: "/etc/x"})
			require.NoError(t, err)
			if state == "missing account" {
				assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
				return
			}
			assert.Equal(t, 1, code)
			assert.True(t, strings.HasPrefix(output, "invalid_archive_path:"), output)
			assert.Empty(t, commandArgv(executor))
		})
	}
}

func TestFirstAddUserHomeOwnership(t *testing.T) {
	for _, platform := range []string{"debian", "rhel"} {
		for _, state := range []string{"another UID", "same UID", "missing", "symlink", "dangling symlink", "custom home", "same UID custom home"} {
			t.Run(platform+"/"+state, func(t *testing.T) {
				h, executor := newHomeTestHandler(t, platform)
				uid := uint64(os.Getuid())
				if uid == 0 {
					uid = 1001
				}
				path := filepath.Join(h.homeRoot, "alice")
				custom := path
				switch state {
				case "symlink":
					require.NoError(t, os.Symlink(t.TempDir(), path))
				case "dangling symlink":
					require.NoError(t, os.Symlink(filepath.Join(h.homeRoot, "missing"), path))
				case "custom home", "same UID custom home":
					path = filepath.Join(t.TempDir(), "custom-home")
					custom = filepath.Dir(path) + "/./" + filepath.Base(path)
					alias := filepath.Join(t.TempDir(), "alias")
					require.NoError(t, os.Symlink(filepath.Dir(path), alias))
					h.readAccountFile = func(string) ([]byte, error) {
						key := "HOME"
						if platform == "debian" {
							key = "DHOME"
						}
						return fmt.Appendf(nil, "%s=%s\n", key, alias), nil
					}
					fallthrough
				case "another UID", "same UID":
					require.NoError(t, os.Mkdir(path, 0755))
					if os.Getuid() == 0 {
						require.NoError(t, os.Chown(path, int(uid), os.Getgid()))
					}
				}
				requested := uid
				if !strings.HasPrefix(state, "same UID") {
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

func TestFirstServiceAccountHomeConflict(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%t", explicit), func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			path := filepath.Join(h.homeRoot, "alice")
			args := &common.CommandArgs{
				Username: "alice", UID: 1001, IsServiceAccount: true,
				Shell: "/bin/bash", Groupname: "alice", Comment: "Alice",
			}
			if explicit {
				path = filepath.Join(t.TempDir(), "custom")
				args.HomeDirectory = path + "/"
			}
			require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), path))
			code, output, err := h.Execute(context.Background(), "adduser", args)
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, "system_home_conflict: "+path+" is a symlink; refusing to create the account", output)
			assert.Empty(t, commandArgv(executor))
		})
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
		{"shared", "another account's home is inside"},
		{"shared descendant", "another account's home is inside"},
		{"shared symlink descendant", "another account's home is inside"},
		{"mounted home", "a filesystem is mounted inside"},
		{"mounted descendant", "a filesystem is mounted inside"},
		{"writable /home", "/home must be root-owned and writable only by root"},
		{"symlinked /home", "/home must be a real directory, symlinks are refused"},
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
				case "mounted descendant":
					home += " with space"
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
				uid += 2
			case "protected":
				name = "nobody"
			case "writable /home":
				require.NoError(t, os.Chmod(h.homeRoot, 0770))
			case "symlinked /home":
				link := filepath.Join(t.TempDir(), "home")
				require.NoError(t, os.Symlink(h.homeRoot, link))
				h.homeRoot = link
				home = filepath.Join(link, "alice")
			case "shared", "shared descendant", "shared symlink descendant":
				otherHome := home + "/./"
				if tc.state == "shared descendant" {
					otherHome += "bob"
				}
				if tc.state == "shared symlink descendant" {
					require.NoError(t, os.Mkdir(filepath.Join(home, "bob"), 0700))
					alias := filepath.Join(t.TempDir(), "alias")
					require.NoError(t, os.Symlink(home, alias))
					otherHome = filepath.Join(alias, "bob")
				}
				readFile := l.readFile
				l.readFile = func(path string) ([]byte, error) {
					if path == "/etc/passwd" {
						return fmt.Appendf(nil, "bob:x:1234:1234::%s:/bin/sh\n", otherHome), nil
					}
					return readFile(path)
				}
			case "mounted home", "mounted descendant":
				point := strings.ReplaceAll(home, " ", `\040`)
				if tc.state == "mounted descendant" {
					point += `/with\040space`
				}
				readFile := l.readFile
				l.readFile = func(path string) ([]byte, error) {
					if path == "/proc/self/mountinfo" {
						return fmt.Appendf(nil, "40 30 0:35 / %s rw - tmpfs tmpfs rw\n", point), nil
					}
					return readFile(path)
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
	for _, activity := range []string{"live processes", "active sessions", "session probe fails", "session probe skips text", "process probe fails"} {
		t.Run(activity, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0700))
			uid := setArchiveTestAccount(t, h, home)
			l := h.accountLocker.(*linuxAccountLocker)
			process := &fakeAccountProcess{}
			switch activity {
			case "process probe fails":
				l.scanProcesses = func(uint64, map[int]accountProcess) ([]accountProcess, error) {
					return nil, errors.New("process probe failed")
				}
			case "live processes":
				l.scanProcesses = func(gotUID uint64, _ map[int]accountProcess) ([]accountProcess, error) {
					assert.Equal(t, uid, gotUID)
					return []accountProcess{process}, nil
				}
			default:
				tool := filepath.Join(t.TempDir(), "loginctl")
				require.NoError(t, os.WriteFile(tool, nil, 0700))
				l.systemd = func() bool { return true }
				l.stat = func(string) (os.FileInfo, error) { return os.Stat(tool) }
				const probe = "/usr/bin/loginctl list-users --no-legend --no-pager"
				switch activity {
				case "session probe fails":
					executor.SetResult(probe, 1, "", errors.New("probe failed"))
				case "session probe skips text":
					executor.SetResult(probe, 0, "No users.\n", nil)
					h.chownHome = func(context.Context, int, string, int, int, int) (int, error) { return 0, nil }
				default:
					executor.SetResult(probe, 0, fmt.Sprintf("UID USER\n%d alice\n", uid), nil)
				}
			}

			archive := "archive"
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: &archive, ArchiveTo: archivePrefix + "alice_2026-11-20T01:02:03Z",
			})
			require.NoError(t, err)
			probeArgv := []string{"/usr/bin/loginctl", "list-users", "--no-legend", "--no-pager"}
			if activity == "session probe skips text" {
				require.Zero(t, code, output)
				assert.Equal(t, [][]string{probeArgv, deleteAlice}, commandArgv(executor))
				return
			}
			assert.Equal(t, 1, code)
			switch activity {
			case "live processes":
				assert.True(t, process.closed)
				assert.Empty(t, commandArgv(executor))
				assert.Equal(t, fmt.Sprintf("user_in_use: UID %d has live processes", uid), output)
			case "process probe fails":
				assert.Contains(t, output, "user_in_use: cannot verify processes")
				assert.Empty(t, commandArgv(executor))
			case "session probe fails":
				assert.Contains(t, output, "user_in_use: cannot verify sessions")
				assert.Equal(t, [][]string{probeArgv}, commandArgv(executor))
			default:
				assert.Equal(t, fmt.Sprintf("user_in_use: UID %d has active sessions", uid), output)
				assert.Equal(t, [][]string{probeArgv}, commandArgv(executor))
			}
			assert.DirExists(t, home)
			_, err = os.Lstat(filepath.Join(h.homeRoot, "deleted_users", "alice_2026-11-20T01:02:03Z"))
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestArchiveRetriesAfterPartialDelete(t *testing.T) {
	const destination = archivePrefix + "alice_2026-11-20T01:02:03Z"
	for _, failure := range []string{"chown", "userdel", "legacy chown", "recreated home"} {
		t.Run(failure, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "alice")
			require.NoError(t, os.Mkdir(home, 0755))
			uid := setArchiveTestAccount(t, h, home)
			var archived string
			attempts := 0
			h.chownHome = func(_ context.Context, _ int, path string, owner, group, linkOwner int) (int, error) {
				attempts++
				if attempts == 1 {
					archived = filepath.Base(path)
				}
				assert.Equal(t, archived, filepath.Base(path))
				assert.Equal(t, 0, owner)
				assert.Equal(t, 0, group)
				assert.Equal(t, int(uid), linkOwner)
				if strings.Contains(failure, "chown") && attempts == 1 {
					return 0, errors.New("ownership failed")
				}
				return 0, nil
			}
			if failure == "userdel" || failure == "recreated home" {
				executor.SetResult("/usr/sbin/userdel alice", 8, "account still active", nil)
			}
			archive := "archive"
			args := &common.CommandArgs{Username: "alice", Home: &archive, ArchiveTo: destination}
			if failure == "legacy chown" {
				args.Home, args.ArchiveTo, args.PurgeHomeDirectory = nil, "", true
			}
			code, output, err := h.Execute(context.Background(), "deluser", args)
			require.NoError(t, err)
			require.Equal(t, 1, code)
			assert.Contains(t, output, "account_delete_failed: home archived to "+archivePrefix+archived+"; ")
			assert.DirExists(t, filepath.Join(h.homeRoot, "deleted_users", archived))
			_, err = os.Lstat(home)
			assert.ErrorIs(t, err, os.ErrNotExist)
			if failure == "userdel" || failure == "recreated home" {
				assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
			} else {
				assert.Empty(t, commandArgv(executor))
			}

			if failure == "userdel" || failure == "recreated home" {
				args.ArchiveTo = archivePrefix + "alice_2026-11-20T01:02:04Z"

			}

			if failure == "recreated home" {
				require.NoError(t, os.Mkdir(home, 0700))
				code, output, err = h.Execute(context.Background(), "deluser", args)
				require.NoError(t, err)
				require.Equal(t, 1, code)
				assert.Contains(t, output, "source home "+home+" exists again")
				assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
				assert.DirExists(t, home)
				require.NoError(t, os.Remove(home))
			}
			executor.SetResult("/usr/sbin/userdel alice", 0, "", nil)
			code, output, err = h.Execute(context.Background(), "deluser", args)
			require.NoError(t, err)
			require.Zero(t, code, output)
			assert.Contains(t, output, archivePrefix+archived)
			if failure == "recreated home" {
				assert.Equal(t, 3, attempts)
			} else {
				assert.Equal(t, 2, attempts)
			}
			entries, err := os.ReadDir(filepath.Join(h.homeRoot, "deleted_users"))
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, archived, entries[0].Name())
		})
	}
}

func TestKeptHomeBlocksUIDReuse(t *testing.T) {
	h, executor := newHomeTestHandler(t, "debian")
	home := filepath.Join(h.homeRoot, "alice")
	require.NoError(t, os.Mkdir(home, 0700))
	uid := setArchiveTestAccount(t, h, home)
	profile := filepath.Join(home, "profile")
	require.NoError(t, os.WriteFile(profile, nil, 0600))
	if os.Geteuid() == 0 {
		require.NoError(t, os.Chown(profile, int(uid), -1))
	}
	code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "alice"})
	require.NoError(t, err)
	require.Zero(t, code, output)
	h.lookupUser = common.AbsentUserLookup
	code, output, err = h.Execute(context.Background(), "adduser", &common.CommandArgs{
		Username: "bob", UID: uid, GID: 1001, HomeDirectory: filepath.Join(h.homeRoot, "bob"),
		Shell: "/bin/bash", Groupname: "bob", Comment: "Bob",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, output, "system_home_conflict: "+home)
	assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
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

func TestConfiguredDefaultHomeConflict(t *testing.T) {
	for _, platform := range []string{"debian", "rhel"} {
		t.Run(platform, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, platform)
			root := t.TempDir()
			path := filepath.Join(root, "alice")
			require.NoError(t, os.Symlink(filepath.Join(root, "missing"), path))
			h.readAccountFile = func(config string) ([]byte, error) {
				if platform == "debian" {
					assert.Equal(t, "/etc/adduser.conf", config)
					return fmt.Appendf(nil, "DHOME = %q\n", root), nil
				}
				assert.Equal(t, "/etc/default/useradd", config)
				return fmt.Appendf(nil, "HOME=%s\n", root), nil
			}
			code, output, err := h.Execute(context.Background(), "adduser", &common.CommandArgs{
				Username: "alice", UID: 1001, IsServiceAccount: true,
				Shell: "/bin/bash", Groupname: "alice", Comment: "Alice",
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Contains(t, output, "system_home_conflict: "+path)
			assert.Empty(t, commandArgv(executor))
		})
	}
}

func TestSharedHomeLookupIgnoresUnrelatedLoop(t *testing.T) {
	h, _ := newHomeTestHandler(t, "debian")
	l := h.accountLocker.(*linuxAccountLocker)
	alias := filepath.Join(t.TempDir(), "loop")
	require.NoError(t, os.Symlink(alias, alias))
	l.readFile = func(string) ([]byte, error) {
		return fmt.Appendf(nil, "bob:x:1234:1234::%s:/bin/sh\n", alias), nil
	}
	require.NoError(t, l.checkSharedHome(context.Background(), "alice", filepath.Join(h.homeRoot, "alice")))
}

func TestSharedHomeLookupCanReleaseCaller(t *testing.T) {
	h, _ := newHomeTestHandler(t, "debian")
	l := h.accountLocker.(*linuxAccountLocker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer func() {
		close(release)
		sharedHomeLookup <- struct{}{}
		<-sharedHomeLookup
	}()
	l.readFile = func(string) ([]byte, error) {
		cancel()
		<-release
		return nil, nil
	}
	err := l.checkSharedHome(ctx, "alice", filepath.Join(h.homeRoot, "alice"))
	require.ErrorIs(t, err, context.Canceled)
	err = l.checkSharedHome(context.Background(), "alice", filepath.Join(h.homeRoot, "alice"))
	require.ErrorContains(t, err, "previous shared-home lookup is still running")
}

func TestCreateServiceAccountWithHomeEntries(t *testing.T) {
	h, executor := newHomeTestHandler(t, "debian")
	home := filepath.Join(h.homeRoot, "alice")
	require.NoError(t, os.Mkdir(home, 0700))
	uid := setArchiveTestAccount(t, h, home)
	h.readAccountFile = h.accountLocker.(*linuxAccountLocker).readFile
	require.NoError(t, os.WriteFile(filepath.Join(home, "profile"), nil, 0600))
	code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "alice"})
	require.NoError(t, err)
	require.Zero(t, code, output)
	h.lookupUser = common.AbsentUserLookup
	code, output, err = h.Execute(context.Background(), "adduser", &common.CommandArgs{
		Username: "bob", IsServiceAccount: true,
		Shell: "/usr/sbin/nologin", Groupname: "bob", Comment: "Bob",
	})
	require.NoError(t, err)
	require.Zero(t, code, output)
	var creation []string
	for _, argv := range commandArgv(executor) {
		if argv[0] == "/usr/sbin/adduser" {
			creation = argv
			break
		}
	}
	require.NotEmpty(t, creation)
	assert.Contains(t, strings.Join(creation, " "), fmt.Sprintf("--uid %d", uid+1))
	assert.Contains(t, creation, filepath.Join(h.homeRoot, "bob"))
}

func TestArchiveMissingHomeEligibility(t *testing.T) {
	const stamp = "_2026-11-20T01:02:03Z"
	for _, name := range []string{"nobody", "alice"} {
		t.Run(name, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			home := filepath.Join(h.homeRoot, "missing")
			uid := setArchiveTestAccount(t, h, home)
			if name == "alice" {
				h.lookupUser = func(name string) (*user.User, error) {
					return &user.User{Username: name, Uid: strconv.FormatUint(uid+2, 10), HomeDir: home}, nil
				}
			}
			mode := "archive"
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: name, Home: &mode, ArchiveTo: archivePrefix + name + stamp,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Contains(t, output, "archive_refused:")
			assert.Empty(t, commandArgv(executor))
		})
	}
}

func TestMissingHomeWithOccupiedArchiveDestination(t *testing.T) {
	h, executor := newHomeTestHandler(t, "debian")
	setArchiveTestAccount(t, h, filepath.Join(h.homeRoot, "alice"))
	const base = "alice_2026-11-20T01:02:03Z"
	parent := filepath.Join(h.homeRoot, "deleted_users")
	require.NoError(t, os.Mkdir(parent, 0700))
	require.NoError(t, os.Mkdir(filepath.Join(parent, base), 0700))

	mode := "archive"
	code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
		Username: "alice", Home: &mode, ArchiveTo: archivePrefix + base,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Equal(t, "invalid_archive_path: destination exists", output)
	assert.Empty(t, commandArgv(executor))
}

func TestDeleteRetriesPendingRecordCleanup(t *testing.T) {
	h, executor := newHomeTestHandler(t, "debian")
	home := filepath.Join(h.homeRoot, "alice")
	require.NoError(t, os.Mkdir(home, 0700))
	setArchiveTestAccount(t, h, home)
	parent := filepath.Join(h.homeRoot, "deleted_users")
	record := filepath.Join(parent, filepath.Base(archiveRecordPath(0, "alice")))
	h.chownHome = func(context.Context, int, string, int, int, int) (int, error) {
		require.NoError(t, os.Remove(record))
		require.NoError(t, os.Mkdir(record, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(record, "child"), nil, 0600))
		return 0, nil
	}

	mode := "archive"
	args := &common.CommandArgs{
		Username: "alice", Home: &mode, ArchiveTo: archivePrefix + "alice_2026-11-20T01:02:03Z",
	}
	code, output, err := h.Execute(context.Background(), "deluser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Contains(t, output, "\npending_record_cleanup_failed: ")

	require.NoError(t, os.Remove(filepath.Join(record, "child")))
	h.lookupUser = common.AbsentUserLookup
	executor.SetResult("/usr/sbin/userdel alice", 6, "user does not exist", nil)
	code, output, err = h.Execute(context.Background(), "deluser", args)
	require.NoError(t, err)
	assert.Equal(t, 6, code)
	assert.NotContains(t, output, "pending_record_cleanup_failed")
	_, err = os.Stat(record)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestKeptHomeBlocksUIDReuseOutsideHomeRoot(t *testing.T) {
	for _, scope := range []string{"configured root", "target parent"} {
		t.Run(scope, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			configuredRoot, targetParent := t.TempDir(), t.TempDir()
			h.readAccountFile = func(string) ([]byte, error) {
				return fmt.Appendf(nil, "DHOME=%s\n", configuredRoot), nil
			}
			parent := configuredRoot
			if scope == "target parent" {
				parent = targetParent
			}
			retained := filepath.Join(parent, "alice")
			require.NoError(t, os.Mkdir(retained, 0700))
			uid := setArchiveTestAccount(t, h, retained)
			h.lookupUser = common.AbsentUserLookup

			code, output, err := h.Execute(context.Background(), "adduser", &common.CommandArgs{
				Username: "bob", UID: uid, GID: 1001, HomeDirectory: filepath.Join(targetParent, "bob"),
				Shell: "/bin/bash", Groupname: "bob", Comment: "Bob",
			})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Contains(t, output, "system_home_conflict: "+retained)
			assert.Empty(t, commandArgv(executor))
		})
	}
}

func TestServiceAccountDefaultHomeMode(t *testing.T) {
	h, executor := newHomeTestHandler(t, "debian")
	target := filepath.Join(t.TempDir(), "profile")
	require.NoError(t, os.WriteFile(target, nil, 0600))
	home := filepath.Join(h.homeRoot, "bob")
	h.Executor = &lockCommandExecutor{MockCommandExecutor: executor, beforeRun: func(_ context.Context, name string, args []string) {
		if name == "/usr/sbin/adduser" {
			require.Contains(t, args, home)
			require.NoError(t, os.Symlink(target, home))
		}
	}}
	code, out, err := h.Execute(context.Background(), "adduser", &common.CommandArgs{Username: "bob", UID: 1001, IsServiceAccount: true, HomeDirectoryPermission: "0711", Groupname: "bob", Shell: "/bin/bash", Comment: "Bob"})
	require.NoError(t, err)
	require.Zero(t, code, out)
	info, err := os.Stat(home)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestServiceAccountUIDRange(t *testing.T) {
	passwd := func(uids ...int) []byte {
		var b []byte
		for i, uid := range uids {
			b = fmt.Appendf(b, "u%d:x:%d:%d::/:/bin/false\n", i, uid, uid)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		uids []int
		want string
	}{
		{"system and nobody IDs do not compete", []int{0, 500, 65534}, "1000"},
		{"above the highest regular UID", []int{65534, 1000, 1004}, "1005"},
		{"range exhausted", []int{60000}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, "debian")
			h.readAccountFile = func(path string) ([]byte, error) {
				if path == "/etc/passwd" {
					return passwd(tc.uids...), nil
				}
				return nil, os.ErrNotExist
			}
			code, out, err := h.Execute(context.Background(), "adduser", &common.CommandArgs{Username: "bob", IsServiceAccount: true, Groupname: "bob", Shell: "/bin/bash", Comment: "Bob"})
			require.NoError(t, err)
			if tc.want == "" {
				require.Equal(t, 1, code, out)
				assert.Contains(t, out, "no service account UID available")
				assert.Empty(t, executor.GetExecutedCommands())
				return
			}
			require.Zero(t, code, out)
			var adduser []string
			for _, c := range executor.GetExecutedCommands() {
				if c.Name == "/usr/sbin/adduser" {
					adduser = c.Args
				}
			}
			require.NotNil(t, adduser)
			assert.Contains(t, strings.Join(adduser, " "), "--uid "+tc.want)
		})
	}
}

func TestHomeScanReleasesAccountGate(t *testing.T) {
	h, _ := newHomeTestHandler(t, "debian")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	h.scanHomeOwners = func(context.Context, string, string, string, bool) homeScanResult {
		cancel()
		<-release
		return homeScanResult{}
	}
	defer func() {
		close(release)
		homeScanSlot <- struct{}{}
		<-homeScanSlot
	}()

	code, output, err := h.Execute(ctx, "adduser", &common.CommandArgs{
		Username: "alice", UID: 1001, GID: 1001, HomeDirectory: filepath.Join(h.homeRoot, "alice"),
		Shell: "/bin/bash", Groupname: "alice", Comment: "Alice",
	})
	require.NoError(t, err)
	require.Equal(t, 1, code)
	require.Contains(t, output, "cannot verify home ownership: context canceled")

	ctx, deadline := context.WithTimeout(context.Background(), time.Second)
	defer deadline()
	code, output, err = h.Execute(ctx, "deluser", &common.CommandArgs{Username: "alice"})
	require.NoError(t, err)
	require.Zero(t, code, output)
}

func TestHomeOwnersDeduplicatesBindMount(t *testing.T) {
	const rootEnv = "ALPAMON_TEST_HOME_OWNER_ROOT"
	if root := os.Getenv(rootEnv); root != "" {
		parent, alias := filepath.Join(root, "parent"), filepath.Join(root, "alias")
		path := filepath.Join(parent, "alice")
		result := scanHomeOwners(context.Background(), path, parent, alias, false)
		require.NoError(t, result.err)
		assert.Empty(t, result.owners)
		assert.NotNil(t, result.target)
		return
	}

	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare unavailable")
	}
	root := t.TempDir()
	parent, alias := filepath.Join(root, "parent"), filepath.Join(root, "alias")
	require.NoError(t, os.MkdirAll(filepath.Join(parent, "alice"), 0700))
	require.NoError(t, os.Mkdir(alias, 0700))
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(unshare, "--user", "--map-root-user", "--mount", "--", "sh", "-c",
		`mount --bind "$1" "$2" || exit 1
printf 'bind mounted\n'
exec "$3" -test.run '^TestHomeOwnersDeduplicatesBindMount$' -test.v`, "sh", parent, alias, exe)
	cmd.Env = append(os.Environ(), rootEnv+"="+root)
	output, err := cmd.CombinedOutput()
	if !strings.Contains(string(output), "bind mounted\n") {
		t.Skipf("unprivileged bind mount unavailable: %s (%v)", output, err)
	}
	require.NoError(t, err, "%s", output)
}

func TestDeleteArchiveRefusedWithoutOpenat2(t *testing.T) {
	h, executor := newHomeTestHandler(t, "rhel")
	home := filepath.Join(h.homeRoot, "alice")
	require.NoError(t, os.Mkdir(home, 0700))
	uid := setArchiveTestAccount(t, h, home)
	original, err := os.Stat(home)
	require.NoError(t, err)

	openat2 := archiveopen.Openat2
	t.Cleanup(func() { archiveopen.Openat2 = openat2 })
	var opened []string
	archiveopen.Openat2 = func(_ int, name string, _ *unix.OpenHow) (int, error) {
		opened = append(opened, name)
		return -1, unix.ENOSYS
	}
	h.accountLocker.(*linuxAccountLocker).renameAt = func(int, string, int, string, uint) error {
		t.Fatal("archive attempted to rename the home without openat2")
		return unix.ENOSYS
	}

	archive := "archive"
	const destination = archivePrefix + "alice_2026-11-20T01:02:03Z"
	code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
		Username: "alice", Home: &archive, ArchiveTo: destination,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, output, "archive_refused: archiving needs Linux 5.6 or later (openat2)")
	assert.Equal(t, []string{"."}, opened)
	_, err = os.Lstat(filepath.Join(h.homeRoot, "deleted_users"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, commandArgv(executor))

	current, err := os.Stat(home)
	require.NoError(t, err)
	assert.True(t, os.SameFile(original, current))
	currentUID, err := fileOwnerUID(current)
	require.NoError(t, err)
	assert.Equal(t, uid, currentUID)
	code, output, err = h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "alice"})
	require.NoError(t, err)
	assert.Zero(t, code, output)
	assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor))
	assert.Equal(t, []string{"."}, opened)

	h.lookupUser = common.AbsentUserLookup
	code, output, err = h.Execute(context.Background(), "deluser", &common.CommandArgs{
		Username: "alice", Home: &archive, ArchiveTo: destination,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, output, "archive_refused: archiving needs Linux 5.6 or later (openat2)")
	assert.Equal(t, [][]string{deleteAlice}, commandArgv(executor), "only the keep request should call userdel")
	assert.Equal(t, []string{".", "."}, opened)
}
