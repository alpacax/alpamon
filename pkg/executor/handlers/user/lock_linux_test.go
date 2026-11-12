package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"golang.org/x/sys/unix"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lockSyncRecorder struct{ calls [][]string }

func (*lockSyncRecorder) CommitSystemInfo()              {}
func (s *lockSyncRecorder) SyncSystemInfo(keys []string) { s.calls = append(s.calls, keys) }

type lockFixture struct {
	h     *UserHandler
	l     *linuxAccountLocker
	exec  *common.MockCommandExecutor
	sync  *lockSyncRecorder
	files map[string]string
}

func newLockFixture(t *testing.T) *lockFixture {
	t.Helper()
	mock := common.NewMockCommandExecutor(t)
	mock.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "", nil)
	mock.SetResult("/bin/systemctl list-units --all --type=service,timer,socket,path --no-legend --no-pager --plain", 0, "", nil)
	sync := &lockSyncRecorder{}
	h := NewUserHandler(mock, nil, sync)
	h.lookupUser = common.ExistingUserLookup("1001")
	l := h.accountLocker.(*linuxAccountLocker)
	l.store = lockStateStore{path: filepath.Join(t.TempDir(), "user-locks.json"), owner: uint32(os.Geteuid())}
	files := map[string]string{
		"/etc/login.defs": "UID_MIN 1000\n",
		"/etc/shadow":     "deploy:hash:20000:0:99999:7::21000:\n",
	}
	l.readFile = func(path string) ([]byte, error) {
		if data, ok := files[path]; ok {
			return []byte(data), nil
		}
		return nil, os.ErrNotExist
	}
	l.systemd = func() bool { return false }
	l.stat = func(string) (os.FileInfo, error) { return os.Stat("/bin/sh") }
	l.lookupUID = func(uid string) (*user.User, error) { return &user.User{Uid: uid}, nil }
	l.terminate = func(ctx context.Context, uid uint64, terminate func(context.Context, []string) error) (int, error) {
		assert.Equal(t, uint64(1001), uid)
		if terminate != nil {
			require.NoError(t, terminate(ctx, nil))
		}
		return 7, nil
	}
	return &lockFixture{h, l, mock, sync, files}
}

func commandArgv(mock *common.MockCommandExecutor) [][]string {
	var result [][]string
	for _, c := range mock.GetExecutedCommands() {
		result = append(result, append([]string{c.Name}, c.Args...))
	}
	return result
}

func TestAccountLockRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		expiry   string
		systemd  bool
		linger   bool
	}{
		{"password and expiry", "hash", "21000", false, false},
		{"already locked password", "!hash", "", true, false},
		{"lingering", "hash", "21000", true, true},
		{"disabled password", "*", "0", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLockFixture(t)
			f.files["/etc/shadow"] = fmt.Sprintf("deploy:%s:20000:0:99999:7::%s:\n", tc.password, tc.expiry)
			f.l.systemd = func() bool { return tc.systemd }
			if tc.linger {
				f.files["/var/lib/systemd/linger/deploy"] = ""
			}
			args := &common.CommandArgs{Username: "deploy", UID: 1001, UIDPresent: true}
			code, result, err := f.h.Execute(context.Background(), "lockuser", args)
			require.NoError(t, err)
			require.Zero(t, code, result)
			assert.Equal(t, `{"username":"deploy","locked":true,"already_locked":false,"processes_ended":7}`, result)
			states, err := f.l.store.load()
			require.NoError(t, err)
			passwordLocked := tc.password[0] == '!'
			assert.Equal(t, accountLockState{UID: 1001, Expiry: tc.expiry, PasswordLocked: passwordLocked, Linger: tc.linger, Locked: true}, states["deploy"])
			info, err := os.Stat(f.l.store.path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
			want := [][]string{{"/usr/sbin/usermod", "-L", "--", "deploy"}, {"/usr/sbin/usermod", "-e", "1", "--", "deploy"}}
			if tc.systemd {
				want = append([][]string{loadedUnitsArgv()}, want...)
			}
			if tc.linger {
				want = append(want, []string{"/usr/bin/loginctl", "disable-linger", "--", "1001"})
			}
			if tc.systemd {
				want = append(want, []string{"/usr/bin/loginctl", "terminate-user", "--", "1001"})
			}
			assert.Equal(t, want, commandArgv(f.exec))

			// Reload the durable entry through a new handler instance.
			restarted := NewUserHandler(f.exec, nil, f.sync)
			restarted.lookupUser = f.h.lookupUser
			locker := restarted.accountLocker.(*linuxAccountLocker)
			locker.store, locker.readFile = f.l.store, f.l.readFile
			locker.systemd, locker.stat = f.l.systemd, f.l.stat
			locker.terminate = func(context.Context, uint64, func(context.Context, []string) error) (int, error) {
				t.Fatal("unlock must not terminate or start processes")
				return 0, nil
			}
			code, result, err = restarted.Execute(context.Background(), "unlockuser", args)
			require.NoError(t, err)
			require.Zero(t, code, result)
			expected := `{"username":"deploy","locked":false,"already_unlocked":false}`
			if tc.linger {
				expected = `{"username":"deploy","locked":false,"already_unlocked":false,"linger_left_disabled":true}`
			}
			assert.Equal(t, expected, result)
			if !passwordLocked {
				want = append(want, []string{"/usr/sbin/usermod", "-U", "--", "deploy"})
			}
			expiry := tc.expiry
			if expiry == "" {
				expiry = "-1"
			}
			want = append(want, []string{"/usr/sbin/usermod", "-e", expiry, "--", "deploy"})
			assert.Equal(t, want, commandArgv(f.exec))
			states, err = f.l.store.load()
			require.NoError(t, err)
			assert.Empty(t, states)
			assert.Equal(t, [][]string{{"groups", "users"}, {"groups", "users"}}, f.sync.calls)
		})
	}
}

func TestAccountLockRefusals(t *testing.T) {
	for _, cmd := range []string{"lockuser", "unlockuser"} {
		for _, tc := range []struct {
			name      string
			username  string
			uid       string
			requested uint64
			present   bool
			defs      string
			reason    string
		}{
			{"upper default", "deploy", "60001", 0, false, "", "refused_system_account"},
			{"upper configured", "deploy", "2001", 0, false, "UID_MAX 2000", "refused_system_account"},
			{"nobody uid", "deploy", "65534", 0, false, "UID_MAX 4294967295", "refused_system_account"},
			{"overflow uid", "deploy", "4294967294", 0, false, "UID_MAX 4294967295", "refused_system_account"},
			{"nobody name", "nobody", "1001", 0, false, "", "refused_system_account"},
			{"nfsnobody name", "nfsnobody", "1001", 0, false, "", "refused_system_account"},
			{"root name", "root", "1001", 0, false, "", "refused_system_account"},
			{"root uid", "deploy", "0", 0, false, "", "refused_system_account"},
			{"system uid", "deploy", "999", 0, false, "", "refused_system_account"},
			{"configured minimum", "deploy", "1001", 0, false, "UID_MIN 2000", "refused_system_account"},
			{"missing account", "deploy", "", 0, false, "", "user_not_found"},
			{"uid mismatch", "deploy", "1001", 1002, true, "", "uid_mismatch"},
			{"explicit zero uid", "deploy", "1001", 0, true, "", "uid_mismatch"},
			{"invalid uid", "deploy", "invalid", 0, false, "", "user_lookup_failed"},
			{"missing name", "", "1001", 0, false, "", "invalid_username"},
			{"option name", "--root", "1001", 0, false, "", "invalid_username"},
			{"path name", "../deploy", "1001", 0, false, "", "invalid_username"},
		} {
			t.Run(cmd+"/"+tc.name, func(t *testing.T) {
				f := newLockFixture(t)
				f.h.lookupUser = common.ExistingUserLookup(tc.uid)
				if tc.uid == "" {
					f.h.lookupUser = common.AbsentUserLookup
				}
				delete(f.files, "/etc/login.defs")
				if tc.defs != "" {
					f.files["/etc/login.defs"] = tc.defs
				}
				code, result, err := f.h.Execute(context.Background(), cmd, &common.CommandArgs{Username: tc.username, UID: tc.requested, UIDPresent: tc.present})
				require.NoError(t, err)
				assert.Equal(t, 1, code)
				assert.True(t, strings.HasPrefix(result, tc.reason+":"), result)
				assert.Empty(t, commandArgv(f.exec))
				assert.Empty(t, f.sync.calls)
				_, err = os.Stat(f.l.store.path)
				assert.ErrorIs(t, err, os.ErrNotExist)
			})
		}
	}
}

func TestAccountLockIdempotency(t *testing.T) {
	f := newLockFixture(t)
	args := &common.CommandArgs{Username: "deploy"}
	for _, tc := range []struct{ cmd, expected string }{
		{"unlockuser", `{"username":"deploy","locked":false,"already_unlocked":true}`},
		{"lockuser", `{"username":"deploy","locked":true,"already_locked":false,"processes_ended":7}`},
		{"lockuser", `{"username":"deploy","locked":true,"already_locked":true,"processes_ended":7}`},
		{"unlockuser", `{"username":"deploy","locked":false,"already_unlocked":false}`},
		{"unlockuser", `{"username":"deploy","locked":false,"already_unlocked":true}`},
	} {
		before := len(commandArgv(f.exec))
		code, result, err := f.h.Execute(context.Background(), tc.cmd, args)
		require.NoError(t, err)
		require.Zero(t, code, result)
		assert.Equal(t, tc.expected, result)
		if strings.Contains(tc.expected, `"already_unlocked":true`) {
			assert.Len(t, commandArgv(f.exec), before)
		}
		if tc.cmd == "lockuser" {
			f.files["/etc/shadow"] = "deploy:!hash:20000:0:99999:7::1:\n"
		} else {
			f.files["/etc/shadow"] = "deploy:hash:20000:0:99999:7::21000:\n"
		}
	}
	assert.Equal(t, []string{"/usr/sbin/usermod", "-e", "21000", "--", "deploy"}, commandArgv(f.exec)[5])
}

func TestAccountLockPartialFailure(t *testing.T) {
	for _, failed := range []string{
		"/usr/sbin/usermod -L -- deploy",
		"/usr/sbin/usermod -e 1 -- deploy",
		"/usr/bin/loginctl disable-linger -- 1001",
		"/usr/sbin/usermod -U -- deploy",
		"/usr/sbin/usermod -e 21000 -- deploy",
	} {
		t.Run(failed, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.files["/var/lib/systemd/linger/deploy"] = ""
			cmd := "lockuser"
			if strings.Contains(failed, "-U") || strings.Contains(failed, "21000") {
				cmd = "unlockuser"
				require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, Expiry: "21000", Linger: true, Locked: true}}))
			}
			f.exec.SetResult(failed, 1, "failed", errors.New("exit status 1"))
			code, result, err := f.h.Execute(context.Background(), cmd, &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Contains(t, result, "account_command_failed:")
			states, err := f.l.store.load()
			require.NoError(t, err)
			assert.Equal(t, "21000", states["deploy"].Expiry)
			assert.False(t, states["deploy"].PasswordLocked)
			assert.Empty(t, f.sync.calls)
		})
	}
}

func TestAccountLockStateSafety(t *testing.T) {
	for _, tc := range []string{"symlink", "mode", "stale uid"} {
		t.Run(tc, func(t *testing.T) {
			f := newLockFixture(t)
			switch tc {
			case "symlink":
				require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), f.l.store.path))
			case "mode":
				require.NoError(t, os.WriteFile(f.l.store.path, []byte(`{}`), 0644))
			case "stale uid":
				require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1002}}))
			}
			code, result, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code, result)
			assert.Empty(t, commandArgv(f.exec))
		})
	}
}

func TestAccountLockTerminationFailure(t *testing.T) {
	f := newLockFixture(t)
	f.l.terminate = func(ctx context.Context, uid uint64, terminate func(context.Context, []string) error) (int, error) {
		var count int
		var err error
		synctest.Test(t, func(t *testing.T) {
			p := &fakeAccountProcess{id: 42, stubborn: true}
			start := time.Now()
			count, err = endAccountProcesses(ctx, uid, terminate, func(_ uint64, tracked map[int]accountProcess) ([]accountProcess, error) {
				if len(tracked) == 0 {
					return []accountProcess{p}, nil
				}
				return nil, nil
			})
			assert.Equal(t, processTerminationBound, time.Since(start))
			assert.True(t, p.closed)
		})
		return count, err
	}
	code, result, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, result, "process_termination_incomplete:")
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.False(t, states["deploy"].Locked)
	assert.Empty(t, f.sync.calls)
}

func TestAccountLockSystemd(t *testing.T) {
	for _, tc := range []struct {
		name, serviceOwner, users   string
		terminateFails, wantFailure bool
	}{
		{"owned service", "deploy", "", false, false},
		{"numeric service owner", "1001", "", false, false},
		{"shared root service", "root", "", false, false},
		{"already absent from logind", "deploy", "0 root\n", true, false},
		{"logind still owns user", "deploy", "1001 deploy\n", true, true},
		{"invalid logind output", "deploy", "invalid\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "worker.service loaded active running worker\n", nil)
			f.exec.SetResult("/usr/bin/systemctl show --property=User --value -- worker.service", 0, tc.serviceOwner, nil)
			if tc.terminateFails {
				f.exec.SetResult("/usr/bin/loginctl terminate-user -- 1001", 1, "failed", errors.New("exit status 1"))
				f.exec.SetResult("/usr/bin/loginctl list-users --no-legend --no-pager", 0, tc.users, nil)
			}
			f.l.terminate = func(ctx context.Context, _ uint64, terminate func(context.Context, []string) error) (int, error) {
				return 1, terminate(ctx, []string{"worker.service"})
			}
			code, result, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			if tc.wantFailure {
				assert.Equal(t, 1, code, result)
			} else {
				assert.Zero(t, code, result)
			}
			want := [][]string{loadedUnitsArgv(), {"/usr/bin/systemctl", "show", "--property=User", "--value", "--", "worker.service"}}
			if tc.serviceOwner != "root" {
				want = append(want, []string{"/usr/bin/systemctl", "show", "--property=UnitFileState", "--value", "--", "worker.service"})
			}
			want = append(want, []string{"/usr/sbin/usermod", "-L", "--", "deploy"}, []string{"/usr/sbin/usermod", "-e", "1", "--", "deploy"})
			if tc.serviceOwner != "root" {
				want = append(want, []string{"/usr/bin/systemctl", "stop", "--no-block", "--job-mode=ignore-dependencies", "--", "worker.service"}, []string{"/usr/bin/systemctl", "disable", "--", "worker.service"})
			}
			want = append(want, []string{"/usr/bin/loginctl", "terminate-user", "--", "1001"})
			if tc.terminateFails {
				want = append(want, []string{"/usr/bin/loginctl", "list-users", "--no-legend", "--no-pager"})
			}
			assert.Equal(t, want, commandArgv(f.exec))
		})
	}
}

func TestAccountLockRechecksIdentity(t *testing.T) {
	f := newLockFixture(t)
	calls := 0
	f.h.lookupUser = func(name string) (*user.User, error) {
		calls++
		if calls == 1 {
			return common.ExistingUserLookup("1001")(name)
		}
		return common.ExistingUserLookup("1002")(name)
	}
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, output, "uid_mismatch:")
	assert.Empty(t, commandArgv(f.exec))
}

func TestNumericAccountLingerUsesVerifiedUID(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.files["/etc/shadow"] = "2000:hash:20000:0:99999:7::21000:\n"
	f.files["/var/lib/systemd/linger/2000"] = ""
	for _, cmd := range []string{"lockuser", "unlockuser"} {
		code, output, err := f.h.Execute(context.Background(), cmd, &common.CommandArgs{Username: "2000", UID: 1001})
		require.NoError(t, err)
		require.Zero(t, code, output)
	}
	assert.Contains(t, commandArgv(f.exec), []string{"/usr/bin/loginctl", "disable-linger", "--", "1001"})
	assert.NotContains(t, commandArgv(f.exec), []string{"/usr/bin/loginctl", "enable-linger", "--", "1001"})
}

func loadedUnitsArgv() []string {
	return []string{"/usr/bin/systemctl", "list-units", "--all", "--type=service,timer,socket,path", "--no-legend", "--no-pager", "--plain"}
}

func TestAccountLockProbeBeforeMutation(t *testing.T) {
	f := newLockFixture(t)
	f.l.pidfdOpen = func(pid, flags int) (int, error) {
		assert.Equal(t, os.Getpid(), pid)
		assert.Zero(t, flags)
		return -1, unix.ENOSYS
	}
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Equal(t, "unsupported_kernel: process handles require Linux 5.3 or later", output)
	assert.Empty(t, commandArgv(f.exec))
	_, err = os.Stat(f.l.store.path)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestAccountLockToolPaths(t *testing.T) {
	for _, tc := range []struct {
		name, missing, prefix string
		running               bool
	}{
		{"usr first", "", "/usr/bin", true},
		{"bin fallback", "/usr/bin", "/bin", true},
		{"missing loginctl", "loginctl", "", true},
		{"missing systemctl", "systemctl", "", true},
		{"no systemd", "all", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLockFixture(t)
			// A regular file at the marker path also establishes systemd presence.
			f.l.systemd = func() bool {
				probe := newAccountLocker(f.h).(*linuxAccountLocker)
				probe.stat = f.l.stat
				return probe.systemd()
			}
			f.l.stat = func(path string) (os.FileInfo, error) {
				if path == "/run/systemd/system" {
					if !tc.running {
						return nil, os.ErrNotExist
					}
				} else if tc.missing == "all" || (tc.missing != "" && strings.Contains(path, tc.missing)) {
					return nil, os.ErrNotExist
				}
				return os.Stat("/bin/sh")
			}
			t.Setenv("PATH", t.TempDir())
			f.files["/var/lib/systemd/linger/deploy"] = ""
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			if tc.running && tc.prefix == "" {
				assert.Equal(t, 1, code)
				assert.Equal(t, "missing_tool: "+tc.missing, output)
				assert.Empty(t, commandArgv(f.exec))
				_, err := os.Stat(f.l.store.path)
				assert.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.Zero(t, code, output)
				if tc.running {
					assert.Contains(t, commandArgv(f.exec), []string{tc.prefix + "/loginctl", "disable-linger", "--", "1001"})
					assert.Equal(t, tc.prefix+"/systemctl", commandArgv(f.exec)[0][0])
				} else {
					assert.Len(t, commandArgv(f.exec), 2)
				}
			}
		})
	}
}

func TestAccountLockLostState(t *testing.T) {
	for _, entry := range []bool{false, true} {
		t.Run(fmt.Sprint(entry), func(t *testing.T) {
			f := newLockFixture(t)
			f.files["/etc/shadow"] = "deploy:!hash:20000:0:99999:7::1:\n"
			if entry {
				require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, StateLost: true}}))
			}
			code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, missingLockState().Error(), output)
			assert.Empty(t, commandArgv(f.exec))
			code, output, err = f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			require.Zero(t, code, output)
			assert.Contains(t, output, `"processes_ended":7`)
			states, err := f.l.store.load()
			require.NoError(t, err)
			assert.Equal(t, accountLockState{UID: 1001, StateLost: true, Locked: true}, states["deploy"])
			before := len(commandArgv(f.exec))
			code, output, err = f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, missingLockState().Error(), output)
			assert.Len(t, commandArgv(f.exec), before)
		})
	}
}

func TestAccountLockRecreatedAccount(t *testing.T) {
	for _, cmd := range []string{"lockuser", "unlockuser"} {
		for _, requested := range []uint64{0, 1001, 1002} {
			for _, held := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/held=%t", cmd, requested, held), func(t *testing.T) {
					f := newLockFixture(t)
					old := accountLockState{UID: 1002, Expiry: "12345", Locked: true, Linger: true}
					require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": old}))
					f.l.lookupUID = func(uid string) (*user.User, error) {
						assert.Equal(t, "1002", uid)
						if held {
							return &user.User{Uid: uid, Username: "other"}, nil
						}
						return nil, user.UnknownUserIdError(1002)
					}
					code, output, err := f.h.Execute(context.Background(), cmd, &common.CommandArgs{Username: "deploy", UID: requested})
					require.NoError(t, err)
					states, err := f.l.store.load()
					require.NoError(t, err)
					if held || requested == 1002 {
						assert.Equal(t, 1, code)
						assert.Contains(t, output, "uid_mismatch:")
						assert.Empty(t, commandArgv(f.exec))
						assert.Equal(t, old, states["deploy"])
					} else {
						require.Zero(t, code, output)
						if cmd == "unlockuser" {
							assert.Empty(t, states)
							assert.Empty(t, commandArgv(f.exec))
						} else {
							assert.Equal(t, uint64(1001), states["deploy"].UID)
							assert.Equal(t, "21000", states["deploy"].Expiry)
							assert.False(t, states["deploy"].Linger)
						}
					}
				})
			}
		}
	}
}

func TestDeleteUserForgetsLock(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f := newLockFixture(t)
			savedPlatform := utils.PlatformLike
			utils.PlatformLike = "debian"
			t.Cleanup(func() { utils.PlatformLike = savedPlatform })
			require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001}, "other": {UID: 1002}}))
			if fail {
				f.exec.SetResult("/usr/sbin/deluser --remove-home deploy", 1, "failed", nil)
			}
			code, output, err := f.h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "deploy", PurgeHomeDirectory: true})
			require.NoError(t, err)
			if fail {
				assert.Equal(t, 1, code)
			} else {
				require.Zero(t, code, output)
			}
			states, err := f.l.store.load()
			require.NoError(t, err)
			_, found := states["deploy"]
			assert.Equal(t, fail, found)
			assert.Contains(t, states, "other")
		})
	}
}

func TestAccountLockCorruptState(t *testing.T) {
	for _, data := range []string{"{", "null", "{} {}", `{"deploy":{"unknown":true}}`} {
		t.Run(data, func(t *testing.T) {
			f := newLockFixture(t)
			f.files["/etc/shadow"] = "deploy:!hash:20000:0:99999:7::1:\n"
			require.NoError(t, os.WriteFile(f.l.store.path, []byte(data), 0600))
			code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, missingLockState().Error(), output)
			assert.Empty(t, commandArgv(f.exec))
			paths, err := filepath.Glob(f.l.store.path + ".corrupt-*")
			require.NoError(t, err)
			require.Len(t, paths, 1)
			info, err := os.Stat(paths[0])
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
			assert.Equal(t, uint32(os.Geteuid()), info.Sys().(*syscall.Stat_t).Uid)
			bytes, err := os.ReadFile(paths[0])
			require.NoError(t, err)
			assert.Equal(t, data, string(bytes))
			states, err := f.l.store.load()
			require.NoError(t, err)
			assert.Empty(t, states)
		})
	}
}

func TestAccountLockRechecksLinger(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	args := &common.CommandArgs{Username: "deploy"}
	for _, linger := range []bool{false, true, false} {
		if linger {
			f.files["/var/lib/systemd/linger/deploy"] = ""
		} else {
			delete(f.files, "/var/lib/systemd/linger/deploy")
		}
		before := len(commandArgv(f.exec))
		code, output, err := f.h.Execute(context.Background(), "lockuser", args)
		require.NoError(t, err)
		require.Zero(t, code, output)
		calls := commandArgv(f.exec)[before:]
		disable := []string{"/usr/bin/loginctl", "disable-linger", "--", "1001"}
		if linger {
			assert.Contains(t, calls, disable)
		} else {
			assert.NotContains(t, calls, disable)
		}
	}
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.True(t, states["deploy"].Linger)
	code, output, err := f.h.Execute(context.Background(), "unlockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, `{"username":"deploy","locked":false,"already_unlocked":false,"linger_left_disabled":true}`, output)
}

func TestAccountLockNullUID(t *testing.T) {
	for _, cmd := range []string{"lockuser", "unlockuser"} {
		f := newLockFixture(t)
		var data protocol.CommandData
		require.NoError(t, json.Unmarshal([]byte(`{"username":"deploy","uid":null}`), &data))
		require.NoError(t, f.h.Validate(cmd, data.ToArgs()))
		code, output, err := f.h.Execute(context.Background(), cmd, data.ToArgs())
		require.NoError(t, err)
		assert.Zero(t, code, output)
	}
}

func TestAccountLockRechecksAfterUsermod(t *testing.T) {
	for _, cmd := range []string{"lockuser", "unlockuser"} {
		for _, after := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d", cmd, after), func(t *testing.T) {
				f := newLockFixture(t)
				if cmd == "unlockuser" {
					require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, Expiry: "21000", Locked: true}}))
				}
				f.h.lookupUser = func(name string) (*user.User, error) {
					uid := "1001"
					if len(commandArgv(f.exec)) >= after {
						uid = "1002"
					}
					return common.ExistingUserLookup(uid)(name)
				}
				code, output, err := f.h.Execute(context.Background(), cmd, &common.CommandArgs{Username: "deploy"})
				require.NoError(t, err)
				assert.Equal(t, 1, code)
				assert.Contains(t, output, "uid_mismatch:")
				assert.Len(t, commandArgv(f.exec), after)
				assert.Empty(t, f.sync.calls)
			})
		}
	}
}

func TestAccountLockLoadedUnits(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	owned := []string{"worker.service", "idle.service", "schedule.timer", "listener.socket", "watch.path"}
	enabled := []string{"worker.service", "schedule.timer", "listener.socket", "watch.path"}
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, strings.Join(append(owned, "root.service", "root.timer"), "\n"), nil)
	for _, unit := range owned {
		service := unit
		if !strings.HasSuffix(unit, ".service") {
			service = "triggered.service"
			f.exec.SetResult("/usr/bin/systemctl show --property=Triggers --value -- "+unit, 0, service, nil)
		}
		f.exec.SetResult("/usr/bin/systemctl show --property=User --value -- "+service, 0, "deploy", nil)
		state := "enabled"
		if unit == "listener.socket" {
			state = "enabled-runtime"
		}
		if unit == "idle.service" {
			state = "disabled"
		}
		f.exec.SetResult("/usr/bin/systemctl show --property=UnitFileState --value -- "+unit, 0, state, nil)
	}
	f.exec.SetResult("/usr/bin/systemctl show --property=User --value -- root.service", 0, "root", nil)
	f.exec.SetResult("/usr/bin/systemctl show --property=Triggers --value -- root.timer", 0, "root.service", nil)
	// No process needs to exist for the loaded units to be stopped and disabled.
	f.l.terminate = func(ctx context.Context, _ uint64, stop func(context.Context, []string) error) (int, error) {
		states, err := f.l.store.load()
		require.NoError(t, err)
		assert.Equal(t, enabled, states["deploy"].EnabledUnits)
		return 0, stop(ctx, nil)
	}
	args := &common.CommandArgs{Username: "deploy"}
	for range 2 {
		before := len(commandArgv(f.exec))
		code, output, err := f.h.Execute(context.Background(), "lockuser", args)
		require.NoError(t, err)
		require.Zero(t, code, output)
		calls := commandArgv(f.exec)[before:]
		for _, unit := range owned {
			assert.Contains(t, calls, []string{"/usr/bin/systemctl", "stop", "--no-block", "--job-mode=ignore-dependencies", "--", unit})
			assert.Contains(t, calls, []string{"/usr/bin/systemctl", "disable", "--", unit})
			f.exec.SetResult("/usr/bin/systemctl show --property=UnitFileState --value -- "+unit, 0, "disabled", nil)
		}
		for _, call := range calls {
			if len(call) > 1 && (call[1] == "stop" || call[1] == "disable") {
				assert.NotContains(t, call, "root.service")
				assert.NotContains(t, call, "root.timer")
			}
		}
	}
	before := len(commandArgv(f.exec))
	code, output, err := f.h.Execute(context.Background(), "unlockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	want := [][]string{{"/usr/sbin/usermod", "-U", "--", "deploy"}, {"/usr/sbin/usermod", "-e", "21000", "--", "deploy"}}
	for _, unit := range enabled {
		want = append(want, []string{"/usr/bin/systemctl", "enable", "--", unit})
	}
	assert.Equal(t, want, commandArgv(f.exec)[before:])
}

func TestAccountLockLingerFailureHasNoClaim(t *testing.T) {
	for _, failed := range []string{"/usr/sbin/usermod -L -- deploy", "/usr/bin/loginctl disable-linger -- 1001"} {
		t.Run(failed, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.files["/var/lib/systemd/linger/deploy"] = ""
			f.exec.SetResult(failed, 1, "failed", nil)
			args := &common.CommandArgs{Username: "deploy"}
			code, output, err := f.h.Execute(context.Background(), "lockuser", args)
			require.NoError(t, err)
			require.Equal(t, 1, code, output)
			code, output, err = f.h.Execute(context.Background(), "unlockuser", args)
			require.NoError(t, err)
			require.Zero(t, code, output)
			assert.Equal(t, `{"username":"deploy","locked":false,"already_unlocked":false}`, output)
		})
	}
}
