package user

import (
	"context"
	"encoding/binary"
	"encoding/json"
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
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type lockCommandExecutor struct {
	*common.MockCommandExecutor
	properties map[string]map[string]string
	sockets    map[string]string
	beforeRun  func(context.Context, string, []string)
}

func (m *lockCommandExecutor) Run(ctx context.Context, name string, args ...string) (int, string, error) {
	if m.beforeRun != nil {
		m.beforeRun(ctx, name, args)
	}
	code, output, err := m.MockCommandExecutor.Run(ctx, name, args...)
	if err != nil || code != 0 || output != "Mock success" || len(args) == 0 {
		return code, output, err
	}
	if args[0] == "show" && len(args) >= 3 && args[1] == "--property="+unitShowProperties {
		var blocks []string
		for _, unit := range args[3:] {
			props := map[string]string{"Id": unit, "User": "root", "LoadState": "loaded", "ActiveState": "inactive"}
			for key, value := range m.properties[unit] {
				props[key] = value
			}
			var block []string
			for _, key := range strings.Split(unitShowProperties, ",") {
				block = append(block, key+"="+props[key])
			}
			blocks = append(blocks, strings.Join(block, "\n"))
		}
		return 0, strings.Join(blocks, "\n\n"), nil
	}
	if args[0] == "cat" {
		var bodies []string
		for _, unit := range args[2:] {
			body, ok := m.sockets[unit]
			if !ok {
				return 1, "missing socket", nil
			}
			bodies = append(bodies, "# /etc/systemd/system/"+unit+"\n"+body)
		}
		return 0, strings.Join(bodies, "\n"), nil
	}
	return code, output, err
}

func setUnitProperty(f *lockFixture, unit, property, value string) {
	if f.exec.properties[unit] == nil {
		f.exec.properties[unit] = make(map[string]string)
	}
	f.exec.properties[unit][property] = value
	f.exec.SetResult("/usr/bin/systemctl show --property="+property+" --value -- "+unit, 0, value, nil)
}

func setSocketConfig(f *lockFixture, unit, body string) { f.exec.sockets[unit] = body }

func TestAccountLockDropIns(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "foo.timer\nlistener.socket\ncustom.socket\nworker@one.service\ntransient.service\nroot.service", nil)
	setUnitProperty(f, "foo.timer", "Triggers", "foo.service")
	for _, unit := range []string{"listener.socket", "custom.socket"} {
		setUnitProperty(f, unit, "Triggers", "")
		setUnitProperty(f, unit, "Accept", "yes")
		setSocketConfig(f, unit, "[Socket]\nAccept=yes\n")
	}
	setSocketConfig(f, "custom.socket", "[Socket]\nService=custom-worker@.service\n")
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
	f.l.terminate = func(ctx context.Context, _ uint64, terminate func(context.Context) error) (int, error) {
		calls := commandArgv(f.exec)
		assert.Contains(t, calls, []string{"/usr/bin/systemctl", "daemon-reload"})
		assert.Contains(t, calls, stop)
		return 7, terminate(ctx)
	}
	args := &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}}
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
	for _, lookupFails := range []bool{false, true} {
		t.Run(fmt.Sprint(lookupFails), func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "unknown.service\nworker.service\nmissing.service", nil)
			setUnitProperty(f, "unknown.service", "User", "missing-account")
			setUnitProperty(f, "missing.service", "User", "missing-account")
			setUnitProperty(f, "worker.service", "User", "deploy")
			setUnitProperty(f, "worker.service", "ActiveState", "active")
			ended := false
			f.l.terminate = func(context.Context, uint64, func(context.Context) error) (int, error) {
				ended = true
				return 1, nil
			}
			f.h.lookupUser = func(name string) (*user.User, error) {
				if name == "deploy" {
					return &user.User{Uid: "1001"}, nil
				}
				if lookupFails {
					return nil, errors.New("not found")
				}
				return nil, user.UnknownUserError(name)
			}
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Contains(t, output, "unit_unresolved: unknown.service")
			assert.Contains(t, output, "unit_block_failed:")
			assert.Contains(t, output, "unit_unresolved: missing.service")
			assert.True(t, ended)
			for _, root := range f.l.files.unitDirs {
				assert.FileExists(t, filepath.Join(root, "worker.service.d", lockDropInName))
			}
			assert.Contains(t, commandArgv(f.exec), []string{"/usr/bin/systemctl", "stop", "--no-block", "--job-mode=ignore-dependencies", "--", "worker.service"})
			assert.Contains(t, commandArgv(f.exec), []string{"/usr/sbin/usermod", "-L", "--", "deploy"})
			assert.Contains(t, commandArgv(f.exec), []string{"/usr/sbin/usermod", "-e", "1", "--", "deploy"})
			assert.FileExists(t, filepath.Join(f.l.files.markerDir, "deploy"))
		})
	}
}

func TestAccountLockDynamicUser(t *testing.T) {
	for _, tc := range []struct {
		name           string
		ownerUID       string
		dynamicUser    string
		showFails      bool
		wantUnresolved bool
		wantDropIn     bool
	}{
		{name: "unknown dynamic user", dynamicUser: "yes"},
		{name: "dynamic property fails", dynamicUser: "yes", showFails: true, wantUnresolved: true},
		{name: "unknown static user", dynamicUser: "no", wantUnresolved: true},
		{name: "existing matching account", ownerUID: "1001", dynamicUser: "yes", wantDropIn: true},
		{name: "existing unrelated account", ownerUID: "1002", dynamicUser: "yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemd = func() bool { return true }
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "dynamic.service", nil)
			setUnitProperty(f, "dynamic.service", "User", "service-account")
			setUnitProperty(f, "dynamic.service", "DynamicUser", tc.dynamicUser)
			setUnitProperty(f, "dynamic.service", "ActiveState", "inactive")
			f.h.lookupUser = func(name string) (*user.User, error) {
				if name == "deploy" {
					return &user.User{Uid: "1001"}, nil
				}
				if tc.ownerUID != "" {
					return &user.User{Uid: tc.ownerUID}, nil
				}
				return nil, user.UnknownUserError(name)
			}
			if tc.showFails {
				f.exec.SetResult("/usr/bin/systemctl show --property="+unitShowProperties+" -- dynamic.service", 1, "", errors.New("show failed"))
			}
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
			require.NoError(t, err)
			if tc.wantUnresolved {
				assert.Equal(t, 1, code, output)
				assert.Contains(t, output, "unit_unresolved: dynamic.service")
			} else {
				assert.Zero(t, code, output)
				assert.NotContains(t, output, "unit_unresolved")
			}
			for _, root := range f.l.files.unitDirs {
				path := filepath.Join(root, "dynamic.service.d", lockDropInName)
				if tc.wantDropIn {
					assert.FileExists(t, path)
				} else {
					_, err := os.Stat(path)
					assert.ErrorIs(t, err, os.ErrNotExist)
				}
			}
			if tc.ownerUID != "" {
				assert.NotContains(t, commandArgv(f.exec), []string{"/usr/bin/systemctl", "show", "--property=DynamicUser", "--value", "--", "dynamic.service"})
			}
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
	setUnitProperty(f, "foo.socket", "Result", "trigger-limit-hit")
	path := filepath.Join(f.l.files.unitDirs[0], "worker.service.d", lockDropInName)
	// A directory at the file path makes unlink fail even as root.
	require.NoError(t, os.MkdirAll(path, 0755))
	require.NoError(t, f.l.files.marker("deploy", true))
	require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, Triggers: []string{"foo.socket"}, DropIns: []string{path, filepath.Join(f.l.files.unitDirs[1], "gone.service.d", lockDropInName)}}}))
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	require.Zero(t, code, output)
	quoted, _ := json.Marshal(path)
	assert.JSONEq(t, `{"username":"deploy","locked":false,"already_unlocked":false,"drop_ins_left":[`+string(quoted)+`],"triggers_left_stopped":["foo.socket"]}`, output)
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.True(t, states["deploy"].CleanupPending)
	assert.Equal(t, []string{path}, states["deploy"].DropIns)
	_, err = os.Stat(filepath.Join(f.l.files.markerDir, "deploy"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestAccountUnlockStateLostCleared(t *testing.T) {
	f := newLockFixture(t)
	require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, StateLost: true}}))
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
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
	states, err = f.l.store.load()
	require.NoError(t, err)
	assert.Empty(t, states)
	paths, err = filepath.Glob(f.l.store.path + ".corrupt-*")
	require.NoError(t, err)
	assert.Len(t, paths, 1)
}

func TestAccountProbeErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{unix.ENOSYS, "unsupported_kernel: process handles require Linux 5.3 or later"}, {unix.EPERM, "unsupported_kernel: process handles are blocked (operation not permitted)"}, {unix.EMFILE, "process_probe_failed: too many open files"}} {
		t.Run(tc.want, func(t *testing.T) {
			f := newLockFixture(t)
			f.l.pidfdOpen = func(int, int) (int, error) { return -1, tc.err }
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
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
			code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
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
				setSocketConfig(f, "worker.socket", "[Socket]\n")
				setUnitProperty(f, "worker@alpamon-lock-probe.service", "User", "deploy")
			}
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, listed, nil)
			path := filepath.Join(f.l.files.unitDirs[0], "worker@.service.d", lockDropInName)
			require.NoError(t, f.l.store.save(map[string]accountLockState{"other": {UID: 1002, DropIns: []string{path}}}))
			code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
			require.NoError(t, err)
			if shared {
				assert.Equal(t, 1, code)
				assert.Contains(t, output, "unit_block_failed: unit_lock_conflict: worker@.service")
				assert.Contains(t, commandArgv(f.exec), []string{"/usr/sbin/usermod", "-L", "--", "deploy"})
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
			setSocketConfig(f, "listener.socket", "[Socket]\nService="+service+"\n")
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
	f.l.terminate = func(ctx context.Context, _ uint64, stop func(context.Context) error) (int, error) {
		ended = true
		return 0, stop(ctx)
	}
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	assert.Equal(t, 1, code, output)
	assert.True(t, ended)
	assert.Contains(t, output, "unit_block_failed:")
	assert.NotContains(t, output, "process_termination_incomplete:")
	states, err := f.l.store.load()
	require.NoError(t, err)
	assert.Len(t, states["deploy"].DropIns, 4)
	assert.Contains(t, commandArgv(f.exec), []string{"/usr/bin/systemctl", "stop", "--no-block", "--job-mode=ignore-dependencies", "--", "one.service", "two.service"})
}

func TestAccountUnlockReportsStoppedTriggers(t *testing.T) {
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
	args := &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}}
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
	before := len(commandArgv(f.exec))
	code, output, err = f.h.Execute(context.Background(), "unlockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, `{"triggers_left_stopped":["foo.socket"],"username":"deploy","locked":false,"already_unlocked":false}`, output)
	for _, call := range commandArgv(f.exec)[before:] {
		assert.NotContains(t, []string{"reset-failed", "start"}, call[1])
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
			code, _, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
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
	assert.True(t, states["deploy"].CleanupPending)
	assert.True(t, states["deploy"].MarkerPending)
	assert.Empty(t, states["deploy"].DropIns)
}

func TestAccountLockReloadFailure(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult("/usr/bin/systemctl daemon-reload", 1, "reload failed", nil)
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	assert.Equal(t, 1, code)
	assert.Contains(t, output, "unit_block_failed:")
	assert.NotContains(t, output, "process_termination_incomplete:")
}

func TestAccountLockInstalledServices(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	f.exec.SetResult("/usr/bin/systemctl list-unit-files --type=service --no-legend", 0, "idle.service disabled enabled\nworker@.service static -\n", nil)
	setUnitProperty(f, "idle.service", "User", "deploy")
	setUnitProperty(f, "idle.service", "Transient", "no")
	setUnitProperty(f, "idle.service", "ActiveState", "inactive")
	code, output, err := f.h.Execute(context.Background(), "lockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	require.Zero(t, code, output)
	for _, root := range f.l.files.unitDirs {
		assert.FileExists(t, filepath.Join(root, "idle.service.d", lockDropInName))
		_, err := os.Stat(filepath.Join(root, "worker@.service.d", lockDropInName))
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	for _, call := range commandArgv(f.exec) {
		assert.NotContains(t, call, "worker@alpamon-lock-probe.service")
	}
}

func TestAccountDropInsRequireDurableRecord(t *testing.T) {
	f := newLockFixture(t)
	require.NoError(t, os.Mkdir(f.l.store.path, 0700))
	state := accountLockState{UID: 1001}
	states := map[string]accountLockState{}
	err := f.l.installDropIns(context.Background(), "deploy", []accountUnit{{name: "worker.service"}, {name: "other.service"}}, states, &state)
	require.ErrorContains(t, err, "lock_state_failed:")
	assert.Len(t, state.DropIns, 4)
	for _, root := range f.l.files.unitDirs {
		for _, service := range []string{"worker.service", "other.service"} {
			_, err := os.Stat(filepath.Join(root, service+".d", lockDropInName))
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
	}
}

func TestAccountUnlockFindsUnrecordedArtifacts(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	require.NoError(t, f.l.files.marker("deploy", true))
	var removed, kept []string
	for _, root := range f.l.files.unitDirs {
		path := filepath.Join(root, "worker.service.d", lockDropInName)
		require.NoError(t, f.l.files.write(path, "[Unit]\nConditionPathExists=!"+filepath.Join(f.l.files.markerDir, "deploy")+"\n", 0644, 0755))
		removed = append(removed, path)
		path = filepath.Join(root, "worker.service.d", "override.conf")
		require.NoError(t, f.l.files.write(path, "[Unit]\nConditionPathExists=!"+filepath.Join(f.l.files.markerDir, "deploy")+"\n", 0644, 0755))
		kept = append(kept, path)
		for _, name := range []string{"deploy-other", "other"} {
			path := filepath.Join(root, name+".service.d", lockDropInName)
			require.NoError(t, f.l.files.write(path, "[Unit]\nConditionPathExists=!"+filepath.Join(f.l.files.markerDir, name)+"\n", 0644, 0755))
			kept = append(kept, path)
		}
	}
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	require.Zero(t, code, output)
	var result struct {
		AlreadyUnlocked bool     `json:"already_unlocked"`
		DropInsRemoved  []string `json:"drop_ins_removed"`
	}
	require.NoError(t, json.Unmarshal([]byte(output), &result))
	assert.True(t, result.AlreadyUnlocked)
	assert.ElementsMatch(t, removed, result.DropInsRemoved)
	for _, path := range append(removed, filepath.Join(f.l.files.markerDir, "deploy")) {
		_, err := os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	for _, path := range kept {
		assert.FileExists(t, path)
	}
	assert.Equal(t, [][]string{{"/usr/bin/systemctl", "daemon-reload"}}, commandArgv(f.exec))
}

func TestAccountCleanupRetries(t *testing.T) {
	for _, command := range []string{"unlockuser", "deluser"} {
		t.Run(command, func(t *testing.T) {
			f := newLockFixture(t)
			saved := utils.PlatformLike
			utils.PlatformLike = "debian"
			t.Cleanup(func() { utils.PlatformLike = saved })
			marker := filepath.Join(f.l.files.markerDir, "deploy")
			path := filepath.Join(f.l.files.unitDirs[0], "worker.service.d", lockDropInName)
			require.NoError(t, os.MkdirAll(marker, 0700))
			require.NoError(t, os.MkdirAll(path, 0755))
			require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1002, Expiry: "12345", DropIns: []string{path}}}))
			require.Error(t, f.l.forget("deploy"))
			states, err := f.l.store.load()
			require.NoError(t, err)
			assert.True(t, states["deploy"].CleanupPending)
			assert.True(t, states["deploy"].MarkerPending)
			assert.Equal(t, []string{path}, states["deploy"].DropIns)
			require.NoError(t, os.Remove(marker))
			require.NoError(t, os.Remove(path))
			require.NoError(t, f.l.files.marker("deploy", true))
			require.NoError(t, f.l.files.write(path, "[Unit]\n", 0644, 0755))
			if command == "deluser" {
				f.h.lookupUser = common.AbsentUserLookup
				f.exec.SetResult("/usr/sbin/deluser --remove-home deploy", 6, "user does not exist", nil)
			}
			code, output, err := f.h.Execute(context.Background(), command, &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}, PurgeHomeDirectory: true})
			require.NoError(t, err)
			if command == "deluser" {
				assert.Equal(t, 6, code)
				assert.Equal(t, "user does not exist", output)
			} else {
				require.Zero(t, code, output)
			}
			states, err = f.l.store.load()
			require.NoError(t, err)
			assert.Empty(t, states)
			for _, file := range []string{marker, path} {
				_, err := os.Stat(file)
				assert.ErrorIs(t, err, os.ErrNotExist)
			}
			for _, call := range commandArgv(f.exec) {
				assert.NotEqual(t, "/usr/sbin/usermod", call[0])
			}
		})
	}
}

func TestAccountReportsOnlyRateLimitedTriggers(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemctl = "/usr/bin/systemctl"
	for unit, result := range map[string]string{"stopped.timer": "success", "broken.socket": "resources", "limited.path": "trigger-limit-hit"} {
		setUnitProperty(f, unit, "Result", result)
	}
	assert.Equal(t, []string{"limited.path"}, f.l.stoppedTriggers(context.Background(), []string{"stopped.timer", "broken.socket", "limited.path"}))
	assert.Equal(t, [][]string{
		{"/usr/bin/systemctl", "show", "--property=Result", "--value", "--", "stopped.timer"},
		{"/usr/bin/systemctl", "show", "--property=Result", "--value", "--", "broken.socket"},
		{"/usr/bin/systemctl", "show", "--property=Result", "--value", "--", "limited.path"},
	}, commandArgv(f.exec))
}

func TestAccountUnlockRemovesUnrecordedMarker(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	require.NoError(t, f.l.files.marker("deploy", true))
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, `{"username":"deploy","locked":false,"already_unlocked":true}`, output)
	_, err = os.Stat(filepath.Join(f.l.files.markerDir, "deploy"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Equal(t, [][]string{{"/usr/bin/systemctl", "daemon-reload"}}, commandArgv(f.exec))
}

func TestAccountUnlockStartsNothing(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	require.NoError(t, f.l.store.save(map[string]accountLockState{"deploy": {UID: 1001, Expiry: "21000", Triggers: []string{"limited.socket", "limited.path", "unreadable.timer", "idle.timer"}}}))
	setUnitProperty(f, "limited.socket", "Result", "trigger-limit-hit")
	setUnitProperty(f, "limited.path", "Result", "trigger-limit-hit")
	setUnitProperty(f, "idle.timer", "Result", "success")
	f.exec.SetResult("/usr/bin/systemctl show --property=Result --value -- unreadable.timer", 1, "unreadable", nil)
	code, output, err := f.h.Execute(context.Background(), "unlockuser", &common.CommandArgs{Username: "deploy", UID: 1001, LockUID: common.OptionalUint64{Value: 1001, Present: true}})
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, `{"triggers_left_stopped":["limited.socket","limited.path","unreadable.timer"],"username":"deploy","locked":false,"already_unlocked":false}`, output)
	for _, call := range commandArgv(f.exec) {
		assert.NotContains(t, []string{"reset-failed", "start"}, call[1])
	}
}

func TestAccountUnitDiscoveryBatches(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemctl = "/usr/bin/systemctl"
	var names []string
	for i := 0; i < 300; i++ {
		names = append(names, fmt.Sprintf("worker-%03d.service", i))
	}
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, strings.Join(names, "\n"), nil)
	units, err := f.l.accountUnits(context.Background(), "deploy", 1001)
	require.NoError(t, err)
	assert.Empty(t, units)
	var shows int
	for _, call := range commandArgv(f.exec) {
		if call[1] == "show" {
			shows++
			assert.LessOrEqual(t, len(call)-4, 128)
			assert.Equal(t, "--property="+unitShowProperties, call[2])
		}
	}
	assert.Equal(t, 3, shows)
}

func TestAccountUnitDiscoveryBadChunk(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(fmt.Sprint(fails), func(t *testing.T) {
			f := newLockFixture(t)
			f.l.systemctl = "/usr/bin/systemctl"
			var names []string
			for i := 0; i < 129; i++ {
				names = append(names, fmt.Sprintf("worker-%03d.service", i))
			}
			f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, strings.Join(names, "\n"), nil)
			command := "/usr/bin/systemctl show --property=" + unitShowProperties + " -- " + strings.Join(names[:128], " ")
			if fails {
				f.exec.SetResult(command, 1, "failed", nil)
			} else {
				f.exec.SetResult(command, 0, "Id=only-one.service\nUser=deploy\n", nil)
			}
			setUnitProperty(f, names[128], "User", "deploy")
			units, err := f.l.accountUnits(context.Background(), "deploy", 1001)
			require.ErrorContains(t, err, "unit_unresolved: "+names[0])
			require.Len(t, units, 1)
			assert.Equal(t, names[128], units[0].name)
		})
	}
}

func TestAccountUnitDeadlinePreservesTermination(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemd = func() bool { return true }
	var names []string
	for i := 0; i < 600; i++ {
		names = append(names, fmt.Sprintf("worker-%03d.service", i))
	}
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, strings.Join(names, "\n"), nil)
	f.exec.beforeRun = func(ctx context.Context, _ string, args []string) {
		if args[0] == "list-units" || args[0] == "list-unit-files" || args[0] == "show" {
			<-ctx.Done()
			assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
		}
	}
	ended := false
	f.l.terminate = func(ctx context.Context, _ uint64, _ func(context.Context) error) (int, error) {
		ended = true
		assert.NoError(t, ctx.Err())
		deadline, ok := ctx.Deadline()
		assert.True(t, ok)
		assert.Equal(t, time.Minute, time.Until(deadline))
		return 1, nil
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		start := time.Now()
		code, output, err := f.h.Execute(ctx, "lockuser", &common.CommandArgs{Username: "deploy", LockUID: common.OptionalUint64{Value: 1001, Present: true}})
		require.NoError(t, err)
		assert.Equal(t, 1, code)
		assert.Contains(t, output, "unit_block_failed:")
		assert.Equal(t, unitWorkTimeout, time.Since(start))
		assert.True(t, ended)
	})
}

func TestAccountDropInsSaveOnceBeforeWriting(t *testing.T) {
	f := newLockFixture(t)
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	require.NoError(t, err)
	defer func() { assert.NoError(t, unix.Close(fd)) }()
	_, err = unix.InotifyAddWatch(fd, filepath.Dir(f.l.store.path), unix.IN_MOVED_TO)
	require.NoError(t, err)
	for _, root := range f.l.files.unitDirs {
		for _, service := range []string{"one.service", "two.service"} {
			dir := filepath.Join(root, service+".d")
			require.NoError(t, os.MkdirAll(dir, 0755))
			_, err = unix.InotifyAddWatch(fd, dir, unix.IN_MOVED_TO)
			require.NoError(t, err)
		}
	}
	states := make(map[string]accountLockState)
	state := accountLockState{UID: 1001}
	require.NoError(t, f.l.installDropIns(context.Background(), "deploy", []accountUnit{{name: "one.service"}, {name: "two.service"}}, states, &state))
	saved, err := f.l.store.load()
	require.NoError(t, err)
	assert.Len(t, saved["deploy"].DropIns, 4)
	var events [4096]byte
	n, err := unix.Read(fd, events[:])
	require.NoError(t, err)
	var saves int
	var names []string
	for offset := 0; offset < n; {
		length := int(binary.NativeEndian.Uint32(events[offset+12 : offset+16]))
		name := strings.TrimRight(string(events[offset+unix.SizeofInotifyEvent:offset+unix.SizeofInotifyEvent+length]), "\x00")
		names = append(names, name)
		if name == filepath.Base(f.l.store.path) {
			saves++
		}
		offset += unix.SizeofInotifyEvent + length
	}
	require.Len(t, names, 5)
	assert.Equal(t, filepath.Base(f.l.store.path), names[0])
	assert.Equal(t, 1, saves)
}

func TestAccountSocketBatchesKeepInheritedOverrides(t *testing.T) {
	f := newLockFixture(t)
	f.l.systemctl = "/usr/bin/systemctl"
	f.exec.SetResult(strings.Join(loadedUnitsArgv(), " "), 0, "foo-one.socket\nworker@one.socket", nil)
	for _, unit := range []string{"foo-one.socket", "worker@one.socket"} {
		setUnitProperty(f, unit, "Accept", "yes")
	}
	f.exec.SetResult("/usr/bin/systemctl cat -- foo-one.socket worker@one.socket", 0, `# /usr/lib/systemd/system/foo-one.socket
[Socket]
Service=default@.service
# /etc/systemd/system/socket.d/global.conf
[Socket]
Service=global@.service
# /etc/systemd/system/foo-.socket.d/override.conf
[Socket]
Service=actual@.service
# /usr/lib/systemd/system/worker@.socket
[Socket]
Service=wrong@.service
# /etc/systemd/system/worker@.socket.d/override.conf
[Socket]
Service=worker-actual@.service
`, nil)
	for _, unit := range []string{"actual@alpamon-lock-probe.service", "worker-actual@alpamon-lock-probe.service"} {
		setUnitProperty(f, unit, "User", "deploy")
	}
	units, err := f.l.accountUnits(context.Background(), "deploy", 1001)
	require.NoError(t, err)
	require.Len(t, units, 2)
	assert.Equal(t, "actual@.service", units[0].name)
	assert.Equal(t, "worker-actual@.service", units[1].name)
	var cats int
	for _, call := range commandArgv(f.exec) {
		if call[1] == "cat" {
			cats++
		}
	}
	assert.Equal(t, 1, cats)
}
