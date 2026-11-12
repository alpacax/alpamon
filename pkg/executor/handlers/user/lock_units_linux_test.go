package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func setUnitProperty(f *lockFixture, unit, property, value string) {
	f.exec.SetResult("/usr/bin/systemctl show --property="+property+" --value -- "+unit, 0, value, nil)
}

func TestAccountLockDropIns(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "foo.timer\nlistener.socket\ncustom.socket\nworker@one.service\ntransient.service\nroot.service", nil)
	setUnitProperty(f, "foo.timer", "Triggers", "foo.service")
	for _, unit := range []string{"listener.socket", "custom.socket"} {
		setUnitProperty(f, unit, "Triggers", "")
		setUnitProperty(f, unit, "Accept", "yes")
		f.exec.SetResult("/usr/bin/systemctl cat -- "+unit, 0, "[Socket]\nAccept=yes\n", nil)
	}
	f.exec.SetResult("/usr/bin/systemctl cat -- custom.socket", 0, "[Socket]\nService=custom-worker@.service\n", nil)
	for _, unit := range []string{"foo.service", "listener@alpamon-lock-probe.service", "custom-worker@alpamon-lock-probe.service", "worker@one.service", "transient.service"} {
		setUnitProperty(f, unit, "User", "deploy")
		setUnitProperty(f, unit, "Transient", "no")
		setUnitProperty(f, unit, "ActiveState", "inactive")
	}
	setUnitProperty(f, "root.service", "User", "root")
	setUnitProperty(f, "foo.service", "ActiveState", "active")
	setUnitProperty(f, "worker@one.service", "ActiveState", "active")
	setUnitProperty(f, "transient.service", "ActiveState", "active")
	setUnitProperty(f, "transient.service", "Transient", "yes")
	stop := []string{"/usr/bin/systemctl", "stop", "--no-block", "--job-mode=ignore-dependencies", "--", "foo.service", "worker@one.service", "transient.service"}
	f.l.terminate = func(ctx context.Context, _ uint64, terminate func(context.Context, []string) error) (int, error) {
		calls := commandArgv(f.exec)
		assert.Contains(t, calls, []string{"/usr/bin/systemctl", "daemon-reload"})
		for _, call := range calls {
			assert.NotEqual(t, "stop", call[1])
		}
		return 7, terminate(ctx, nil)
	}
	args := &common.CommandArgs{Username: "deploy"}
	code, output, err := f.h.Execute(context.Background(), "lockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	states, err := f.l.store.load()
	require.NoError(t, err)
	require.Len(t, states["deploy"].DropIns, 8)
	for _, root := range f.l.files.unitDirs {
		for _, unit := range []string{"foo.service", "listener@.service", "custom-worker@.service", "worker@one.service"} {
			path := filepath.Join(root, unit+".d", lockDropInName)
			assert.Contains(t, states["deploy"].DropIns, path)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "[Unit]\nConditionPathExists=!"+filepath.Join(f.l.files.markerDir, "deploy")+"\n", string(data))
			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
		}
	}
	marker := filepath.Join(f.l.files.markerDir, "deploy")
	info, err := os.Stat(marker)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	info, err = os.Stat(f.l.files.markerDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
	calls := commandArgv(f.exec)
	assert.Contains(t, calls, stop)
	stops, reloads := 0, 0
	for _, call := range calls {
		if call[1] == "stop" {
			stops++
		}
		if call[1] == "daemon-reload" {
			reloads++
		}
		assert.NotEqual(t, "disable", call[1])
	}
	assert.Equal(t, 1, stops)
	assert.Equal(t, 1, reloads)
	before := len(calls)
	code, output, err = f.h.Execute(context.Background(), "unlockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, `{"username":"deploy","locked":false,"already_unlocked":false}`, output)
	_, err = os.Stat(marker)
	assert.ErrorIs(t, err, os.ErrNotExist)
	for _, path := range states["deploy"].DropIns {
		_, err := os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	assert.Equal(t, [][]string{{"/usr/sbin/usermod", "-U", "--", "deploy"}, {"/usr/sbin/usermod", "-e", "21000", "--", "deploy"}, {"/usr/bin/systemctl", "daemon-reload"}}, commandArgv(f.exec)[before:])
}

func TestAccountLockUnitUnresolved(t *testing.T) {
	for _, showFails := range []bool{false, true} {
		t.Run(fmt.Sprint(showFails), func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "unknown.service", nil)
			setUnitProperty(f, "unknown.service", "User", "missing-account")
			f.h.lookupUser = func(name string) (*user.User, error) {
				if name == "deploy" {
					return &user.User{Uid: "1001"}, nil
				}
				return nil, errors.New("not found")
			}
			if showFails {
				f.exec.SetResult("/usr/bin/systemctl show --property=User --value -- unknown.service", 1, "failed", nil)
			}
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Contains(t, output, "unit_unresolved: unknown.service")
			for _, call := range commandArgv(f.exec) {
				assert.Contains(t, []string{"show", "list-units"}, call[1])
			}
			_, err = os.Stat(f.l.store.path)
			assert.ErrorIs(t, err, os.ErrNotExist)
			_, err = os.Stat(f.l.files.markerDir)
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestAccountStopTransientFailure(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemctl = "/usr/bin/systemctl"
	units := []accountUnit{{name: "gone.service", transient: true, running: true}, {name: "worker.service", running: true}}
	f.exec.SetResult("/usr/bin/systemctl stop --no-block --job-mode=ignore-dependencies -- gone.service worker.service", 1, "gone", nil)
	setUnitProperty(f, "worker.service", "ActiveState", "deactivating")
	require.NoError(t, f.l.stopServices(context.Background(), "deploy", 1001, units))
	setUnitProperty(f, "worker.service", "ActiveState", "active")
	setUnitProperty(f, "worker.service", "Job", "")
	require.Error(t, f.l.stopServices(context.Background(), "deploy", 1001, units))
}

func TestAccountUnlockDropInsLeft(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult("/usr/bin/systemctl daemon-reload", 1, "reload failed", nil)
	setUnitProperty(f, "foo.socket", "ActiveState", "inactive")
	f.exec.SetResult("/usr/bin/systemctl start -- foo.socket", 1, "failed", nil)
	path := filepath.Join(f.l.files.unitDirs[0], "worker.service.d", lockDropInName)
	// A directory at the file path makes unlink fail even as root.
	require.NoError(t, os.MkdirAll(path, 0755))
	require.NoError(t, f.l.files.marker("deploy", true))
	require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, Triggers: []string{"foo.socket"}, DropIns: []string{path, filepath.Join(f.l.files.unitDirs[1], "gone.service.d", lockDropInName)}}}))
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
	require.NoError(t, err)
	require.Zero(t, code, output)
	quoted, _ := json.Marshal(path)
	assert.JSONEq(t, `{"username":"deploy","locked":false,"already_unlocked":false,"drop_ins_left":[`+string(quoted)+`],"triggers_not_restored":["foo.socket"]}`, output)
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Empty(t, states)
	_, err = os.Stat(filepath.Join(f.l.files.markerDir, "deploy"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestAccountUnlockStateLostCleared(t *testing.T) {
	f := newLockFixture(t)
	require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, StateLost: true}}))
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, `{"username":"deploy","locked":false,"already_unlocked":true}`, output)
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Empty(t, states)
	assert.Empty(t, commandArgv(f.exec))
}

func TestAccountStateUnknownFields(t *testing.T) {
	f := newLockFixture(t)
	data := `{"deploy":{"uid":1001,"expiry":"21000","enabled_units":["old.service"],"future":true}}`
	require.NoError(t, os.WriteFile(f.l.store.path, []byte(data), 0600))
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Equal(t, uint64(1001), states["deploy"].UID)
	require.NoError(t, f.l.store.save(states))
	bytes, err := os.ReadFile(f.l.store.path)
	require.NoError(t, err)
	assert.NotContains(t, string(bytes), "enabled_units")
	paths, err := filepath.Glob(f.l.store.path + ".corrupt-*")
	require.NoError(t, err)
	assert.Empty(t, paths)
	require.NoError(t, os.WriteFile(f.l.store.path, []byte(`{"deploy":{"uid":"bad"}}`), 0600))
	_, err = f.l.store.load()
	require.Error(t, err)
	paths, err = filepath.Glob(f.l.store.path + ".corrupt-*")
	require.NoError(t, err)
	assert.Empty(t, paths)
}

func TestAccountProbeErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{unix.ENOSYS, "unsupported_kernel: process handles require Linux 5.3 or later"}, {unix.EPERM, "unsupported_kernel: process handles are blocked (operation not permitted)"}, {unix.EMFILE, "process_probe_failed: too many open files"}} {
		t.Run(tc.want, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.pidfdOpen = func(int, int) (int, error) { return -1, tc.err }
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, tc.want, output)
			assert.Empty(t, commandArgv(f.exec))
			_, err = os.Stat(f.l.store.path)
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestDeleteUserForgetFailure(t *testing.T) {
	f := newLockFixture(t)
	saved := utils.PlatformLike
	utils.PlatformLike = "debian"
	t.Cleanup(func() { utils.PlatformLike = saved })
	require.NoError(t, os.Mkdir(f.l.store.path, 0700))
	code, output, err := f.h.Execute(context.Background(), "deluser", &common.CommandArgs{Username: "deploy", PurgeHomeDirectory: true})
	require.NoError(t, err)
	assert.Zero(t, code, output)
	assert.Contains(t, output, "deleted successfully")
}

func TestLockFilesRejectSymlinks(t *testing.T) {
	f := newLockFixture(t)
	target := t.TempDir()
	require.NoError(t, os.Symlink(target, f.l.files.markerDir))
	require.Error(t, f.l.files.marker("deploy", true))
	require.Error(t, f.l.files.marker("../deploy", true))
	root := f.l.files.unitDirs[0]
	require.NoError(t, os.Mkdir(root, 0755))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "worker.service.d")))
	require.Error(t, f.l.files.write(filepath.Join(root, "worker.service.d", lockDropInName), "test", 0644, 0755))
}

func TestAccountUnlockRecoveredArtifacts(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			path := filepath.Join(f.l.files.unitDirs[0], "worker.service.d", lockDropInName)
			require.NoError(t, f.l.files.write(path, "[Unit]\n", 0644, 0755))
			require.NoError(t, f.l.files.marker("deploy", true))
			state := accountLockState{UID: 1001, StateLost: true, DropIns: []string{path}}
			if stale {
				state.UID = 1002
				f.l.lookupUID = func(string) (*user.User, error) { return nil, user.UnknownUserIdError(1002) }
			}
			require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": state}))
			code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			require.Zero(t, code, output)
			assert.Contains(t, output, `"already_unlocked":true`)
			_, err = os.Stat(filepath.Join(f.l.files.markerDir, "deploy"))
			assert.ErrorIs(t, err, os.ErrNotExist)
			_, err = os.Stat(path)
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.Equal(t, [][]string{{"/usr/bin/systemctl", "daemon-reload"}}, commandArgv(f.exec))
		})
	}
}

func TestAccountLockTemplateCollision(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			listed := "worker@deploy.service"
			setUnitProperty(f, listed, "User", "deploy")
			if shared {
				listed = "worker.socket"
				setUnitProperty(f, listed, "Triggers", "")
				setUnitProperty(f, listed, "Accept", "yes")
				f.exec.SetResult("/usr/bin/systemctl cat -- worker.socket", 0, "[Socket]\n", nil)
				setUnitProperty(f, "worker@alpamon-lock-probe.service", "User", "deploy")
			}
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, listed, nil)
			path := filepath.Join(f.l.files.unitDirs[0], "worker@.service.d", oldLockDropInName)
			require.NoError(t, f.l.store.save(map[string]accountLockState{"other": {UID: 1002, DropIns: []string{path}}}))
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			if shared {
				assert.Equal(t, 1, code)
				assert.Equal(t, "unit_lock_conflict: worker@.service", output)
				for _, call := range commandArgv(f.exec) {
					assert.NotEqual(t, "/usr/sbin/usermod", call[0])
				}
			} else {
				assert.Zero(t, code, output)
			}
		})
	}
}

func TestAccountLockUnresolvedSocketService(t *testing.T) {
	for _, service := range []string{"%p@.service", "missing@.service"} {
		t.Run(service, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemctl = "/usr/bin/systemctl"
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "listener.socket", nil)
			setUnitProperty(f, "listener.socket", "Triggers", "")
			setUnitProperty(f, "listener.socket", "Accept", "yes")
			f.exec.SetResult("/usr/bin/systemctl cat -- listener.socket", 0, "[Socket]\nService="+service+"\n", nil)
			setUnitProperty(f, "missing@alpamon-lock-probe.service", "User", "")
			setUnitProperty(f, "missing@alpamon-lock-probe.service", "LoadState", "not-found")
			_, err := f.l.accountUnits(context.Background(), "deploy", 1001)
			require.ErrorContains(t, err, "unit_unresolved:")
		})
	}
}

func TestAccountLockContinuesAfterDropInError(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "one.service\ntwo.service", nil)
	for _, unit := range []string{"one.service", "two.service"} {
		setUnitProperty(f, unit, "User", "deploy")
		setUnitProperty(f, unit, "ActiveState", "active")
	}
	blocked := filepath.Join(f.l.files.unitDirs[1], "one.service.d", lockDropInName)
	require.NoError(t, os.MkdirAll(blocked, 0755))
	ended := false
	f.l.terminate = func(ctx context.Context, _ uint64, stop func(context.Context, []string) error) (int, error) {
		ended = true
		return 0, stop(ctx, nil)
	}
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
	require.NoError(t, err)
	assert.Equal(t, 1, code, output)
	assert.True(t, ended)
	assert.Contains(t, output, "unit_block_failed:")
	assert.NotContains(t, output, "process_termination_incomplete:")
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Len(t, states["deploy"].DropIns, 3)
	assert.Contains(t, commandArgv(f.exec), []string{"/usr/bin/systemctl", "stop", "--no-block", "--job-mode=ignore-dependencies", "--", "one.service", "two.service"})
}

func TestAccountUnlockRestoresTriggers(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "foo.socket\nfoo.path\nfoo.timer\nidle.timer\nroot.socket", nil)
	for _, unit := range []string{"foo.socket", "foo.path", "foo.timer", "idle.timer", "root.socket"} {
		setUnitProperty(f, unit, "Triggers", "foo.service")
		setUnitProperty(f, unit, "ActiveState", "active")
		setUnitProperty(f, unit, "Accept", "no")
	}
	setUnitProperty(f, "idle.timer", "ActiveState", "inactive")
	setUnitProperty(f, "root.socket", "Triggers", "root.service")
	setUnitProperty(f, "root.service", "User", "root")
	setUnitProperty(f, "foo.service", "User", "deploy")
	setUnitProperty(f, "foo.service", "ActiveState", "inactive")
	args := &common.CommandArgs{Username: "deploy"}
	code, output, err := f.h.Execute(context.Background(), "lockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Equal(t, []string{"foo.socket", "foo.path", "foo.timer"}, states["deploy"].Triggers)
	// Re-locking while triggers are failed preserves the original active set.
	setUnitProperty(f, "foo.socket", "ActiveState", "failed")
	code, output, err = f.h.Execute(context.Background(), "lockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	setUnitProperty(f, "foo.socket", "Result", "trigger-limit-hit")
	setUnitProperty(f, "foo.path", "ActiveState", "inactive")
	f.exec.SetResult("/usr/bin/systemctl start -- foo.socket", 1, "cannot start", nil)
	f.exec.SetResult("/usr/bin/systemctl start -- foo.path", 1, "cannot start", nil)
	before := len(commandArgv(f.exec))
	code, output, err = f.h.Execute(context.Background(), "unlockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.JSONEq(t, `{"username":"deploy","locked":false,"already_unlocked":false,"triggers_not_restored":["foo.socket","foo.path"]}`, output)
	calls := commandArgv(f.exec)[before:]
	assert.Contains(t, calls, []string{"/usr/bin/systemctl", "reset-failed", "--", "foo.socket", "foo.path", "foo.timer"})
	assert.Contains(t, calls, []string{"/usr/bin/systemctl", "start", "--", "foo.socket"})
	assert.Contains(t, calls, []string{"/usr/bin/systemctl", "start", "--", "foo.path"})
	for _, call := range calls {
		if call[1] == "start" {
			assert.Contains(t, []string{"foo.socket", "foo.path"}, call[3])
		}
	}
}

func TestAccountUnlockKeepsArtifactsOnRestoreFailure(t *testing.T) {
	for _, command := range []string{"-U -- deploy", "-e 21000 -- deploy"} {
		t.Run(command, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			path := filepath.Join(f.l.files.unitDirs[0], "foo.service.d", lockDropInName)
			require.NoError(t, f.l.files.write(path, "[Unit]\n", 0644, 0755))
			require.NoError(t, f.l.files.marker("deploy", true))
			require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, Expiry: "21000", DropIns: []string{path}}}))
			f.exec.SetResult("/usr/sbin/usermod "+command, 1, "failed", nil)
			code, _, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.FileExists(t, path)
			assert.FileExists(t, filepath.Join(f.l.files.markerDir, "deploy"))
			states, err := f.l.store.load()
			require.NoError(t, err)
			assert.Contains(t, states, "deploy")
			for _, call := range commandArgv(f.exec) {
				assert.NotEqual(t, "/usr/bin/systemctl", call[0])
			}
		})
	}
}

func TestAccountUnlockRemovesBothDropInNames(t *testing.T) {
	assert.Greater(t, lockDropInName, "override.conf")
	for _, recorded := range []string{oldLockDropInName, lockDropInName} {
		for _, keepOverride := range []bool{false, true} {
			t.Run(fmt.Sprint(recorded, keepOverride), func(t *testing.T) {
				f := newLockFixture(t)
				f.l.systemd = func() bool { return true }
				dir := filepath.Join(f.l.files.unitDirs[0], "foo.service.d")
				for _, base := range []string{oldLockDropInName, lockDropInName} {
					require.NoError(t, f.l.files.write(filepath.Join(dir, base), "[Unit]\n", 0644, 0755))
				}
				if keepOverride {
					require.NoError(t, os.WriteFile(filepath.Join(dir, "override.conf"), []byte("[Service]\n"), 0644))
				}
				require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, DropIns: []string{filepath.Join(dir, recorded)}}}))
				code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy"})
				require.NoError(t, err)
				require.Zero(t, code, output)
				assert.NotContains(t, output, "drop_ins_left")
				for _, base := range []string{oldLockDropInName, lockDropInName} {
					_, err := os.Stat(filepath.Join(dir, base))
					assert.ErrorIs(t, err, os.ErrNotExist)
				}
				if keepOverride {
					assert.FileExists(t, filepath.Join(dir, "override.conf"))
				} else {
					_, err := os.Stat(dir)
					assert.ErrorIs(t, err, os.ErrNotExist)
				}
			})
		}
	}
}

func TestAccountForgetContinuesAfterMarkerError(t *testing.T) {
	f := newLockFixture(t)
	path := filepath.Join(f.l.files.unitDirs[0], "foo.service.d", lockDropInName)
	require.NoError(t, f.l.files.write(path, "[Unit]\n", 0644, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(f.l.files.markerDir, "deploy"), 0700))
	require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, DropIns: []string{path}}}))
	require.Error(t, f.l.forget("deploy"))
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Empty(t, states)
}

func TestAccountLockReloadFailure(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult("/usr/bin/systemctl daemon-reload", 1, "reload failed", nil)
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy"})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, output, "unit_block_failed:")
	assert.NotContains(t, output, "process_termination_incomplete:")
}
