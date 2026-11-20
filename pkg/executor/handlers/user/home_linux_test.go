package user

import (
	"context"
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
	return h, executor
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
		{name: "explicit keep", platform: "rhel", home: &keep, dest: "ignored"},
		{name: "archive passwd home", platform: "rhel", home: &archive, dest: archiveTo},
		{name: "missing passwd home", platform: "debian", home: &archive, dest: archiveTo, absent: true},
		{name: "legacy purge archives", platform: "debian", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, executor := newHomeTestHandler(t, tc.platform)
			home := filepath.Join(t.TempDir(), "custom-home")
			if !tc.absent {
				require.NoError(t, os.Mkdir(home, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(home, "file"), []byte("saved"), 0600))
			}
			h.lookupUser = func(name string) (*user.User, error) {
				return &user.User{Username: name, Uid: "1001", HomeDir: home}, nil
			}
			var chowned []string
			h.chownHome = func(path string, uid, gid, linkOwner int) (int, error) {
				assert.Equal(t, 0, uid)
				assert.Equal(t, 0, gid)
				chowned = append(chowned, path)
				assert.Empty(t, commandArgv(executor), "archive ownership must be set before deletion")
				return 0, nil
			}
			code, output, err := h.Execute(context.Background(), "deluser", &common.CommandArgs{
				Username: "alice", Home: tc.home, ArchiveTo: tc.dest, PurgeHomeDirectory: tc.legacy,
			})
			require.NoError(t, err)
			require.Zero(t, code, output)
			assert.Equal(t, [][]string{{"/usr/sbin/userdel", "alice"}}, commandArgv(executor))
			parent := filepath.Join(h.homeRoot, "deleted_users")
			switch {
			case tc.absent:
				assert.Equal(t, "User 'alice' deleted; home directory "+home+" not found; nothing archived", output)
				assert.Empty(t, chowned)
			case !tc.legacy && (tc.home == nil || *tc.home == keep):
				assert.Equal(t, "User 'alice' deleted; home directory kept at "+home, output)
				assert.FileExists(t, filepath.Join(home, "file"))
				assert.Empty(t, chowned)
			default:
				require.Len(t, chowned, 2)
				assert.Equal(t, parent, chowned[0])
				archived := chowned[1]
				name := filepath.Base(archived)
				want := "User 'alice' deleted; home directory archived to " + archivePrefix + name
				if tc.legacy {
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
			home := t.TempDir()
			h.lookupUser = func(name string) (*user.User, error) {
				return &user.User{Username: name, Uid: "1001", HomeDir: home}, nil
			}
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
		for _, state := range []string{"another UID", "same UID", "missing"} {
			t.Run(platform+"/"+state, func(t *testing.T) {
				h, executor := newHomeTestHandler(t, platform)
				uid := uint64(os.Getuid())
				if uid == 0 {
					uid = 1001
				}
				if state != "missing" {
					path := filepath.Join(h.homeRoot, "alice")
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
					Username: "alice", UID: requested, GID: 1001, HomeDirectory: "/home/alice",
					Shell: "/bin/bash", Groupname: "alice", Comment: "Alice",
				}
				code, output, err := h.Execute(context.Background(), "adduser", args)
				require.NoError(t, err)
				if state == "another UID" {
					assert.Equal(t, 1, code)
					assert.Equal(t, fmt.Sprintf("system_home_conflict: /home/alice is owned by uid %d, not %d; refusing to create the account", uid, requested), output)
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
