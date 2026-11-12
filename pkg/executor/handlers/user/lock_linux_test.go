package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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
			passwordLocked := tc.password[0] == '!' || tc.password[0] == '*'
			assert.Equal(t, accountLockState{1001, tc.expiry, passwordLocked, tc.linger, true}, states["deploy"])
			info, err := os.Stat(f.l.store.path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
			want := [][]string{{"/usr/sbin/usermod", "-L", "--", "deploy"}, {"/usr/sbin/usermod", "-e", "1", "--", "deploy"}}
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
			locker.terminate = func(context.Context, uint64, func(context.Context, []string) error) (int, error) {
				t.Fatal("unlock must not terminate or start processes")
				return 0, nil
			}
			code, result, err = restarted.Execute(context.Background(), "unlockuser", args)
			require.NoError(t, err)
			require.Zero(t, code, result)
			assert.Equal(t, `{"username":"deploy","locked":false,"already_unlocked":false}`, result)
			if !passwordLocked {
				want = append(want, []string{"/usr/sbin/usermod", "-U", "--", "deploy"})
			}
			expiry := tc.expiry
			if expiry == "" {
				expiry = "-1"
			}
			want = append(want, []string{"/usr/sbin/usermod", "-e", expiry, "--", "deploy"})
			if tc.linger {
				want = append(want, []string{"/usr/bin/loginctl", "enable-linger", "--", "1001"})
			}
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
		"/usr/bin/loginctl enable-linger -- 1001",
	} {
		t.Run(failed, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.files["/var/lib/systemd/linger/deploy"] = ""
			cmd := "lockuser"
			if strings.Contains(failed, "-U") || strings.Contains(failed, "21000") || strings.Contains(failed, "enable-linger") {
				cmd = "unlockuser"
				require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {1001, "21000", false, true, true}}))
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
	for _, tc := range []string{"symlink", "mode", "malformed", "stale uid"} {
		t.Run(tc, func(t *testing.T) {
			f := newLockFixture(t)
			switch tc {
			case "symlink":
				require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), f.l.store.path))
			case "mode":
				require.NoError(t, os.WriteFile(f.l.store.path, []byte(`{}`), 0644))
			case "malformed":
				require.NoError(t, os.WriteFile(f.l.store.path, []byte(`{`), 0600))
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
			want := [][]string{
				{"/usr/sbin/usermod", "-L", "--", "deploy"},
				{"/usr/sbin/usermod", "-e", "1", "--", "deploy"},
				{"/usr/bin/systemctl", "show", "--property=User", "--value", "--", "worker.service"},
			}
			if tc.serviceOwner != "root" {
				want = append(want, []string{"/usr/bin/systemctl", "stop", "--no-block", "--", "worker.service"})
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
	assert.Contains(t, commandArgv(f.exec), []string{"/usr/bin/loginctl", "enable-linger", "--", "1001"})
}
