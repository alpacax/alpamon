//go:build linux && integration

package user_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	userhandler "github.com/alpacax/alpamon/v2/pkg/executor/handlers/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountLockSystemdIntegration(t *testing.T) {
	if os.Getenv("ALPAMON_SYSTEMD_INTEGRATION") != "1" {
		t.Skip("requires the isolated systemd integration runner")
	}
	require.Zero(t, os.Geteuid())
	comm, err := os.ReadFile("/proc/1/comm")
	require.NoError(t, err)
	require.Equal(t, "systemd", strings.TrimSpace(string(comm)))
	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		require.NoError(t, err, "%v: %s", args, output)
		return strings.TrimSpace(string(output))
	}
	name := "alpamon-systemd-test"
	run("/usr/sbin/useradd", "-m", "-s", "/bin/sh", name)
	run("/usr/sbin/usermod", "-p", "synthetic-test-hash", name)
	home := "/home/" + name
	foo := filepath.Join(home, "timer-started")
	socketStarted := filepath.Join(home, "socket-started")
	customStarted := filepath.Join(home, "custom-started")
	socketPath := "/run/alpamon-lock-test.sock"
	units := map[string]string{
		"alpamon-lock-foo.service":            "[Service]\nType=oneshot\nUser=" + name + "\nExecStart=/usr/bin/touch " + foo + "\n[Install]\nWantedBy=multi-user.target\nAlso=alpamon-lock-root.service\n",
		"alpamon-lock-foo.timer":              "[Timer]\nOnActiveSec=100ms\nAccuracySec=1ms\nUnit=alpamon-lock-foo.service\n",
		"alpamon-lock-listener.socket":        "[Socket]\nListenStream=" + socketPath + "\nAccept=yes\n",
		"alpamon-lock-listener@.service":      "[Service]\nUser=" + name + "\nExecStart=/usr/bin/touch " + socketStarted + "\nStandardInput=socket\n",
		"alpamon-lock-custom.socket":          "[Socket]\nListenStream=/run/alpamon-lock-custom.sock\nAccept=yes\nService=alpamon-lock-custom-worker@.service\n",
		"alpamon-lock-custom-worker@.service": "[Service]\nUser=" + name + "\nExecStart=/usr/bin/touch " + customStarted + "\nStandardInput=socket\n",
		"alpamon-lock-root.service":           "[Service]\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n",
		"alpamon-lock-runtime.service":        "[Service]\nUser=" + name + "\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n",
	}
	for unit, body := range units {
		require.NoError(t, os.WriteFile(filepath.Join("/etc/systemd/system", unit), []byte(body), 0644))
	}
	run("/usr/bin/systemctl", "daemon-reload")
	run("/usr/bin/systemctl", "enable", "alpamon-lock-foo.service")
	run("/usr/bin/systemctl", "enable", "--runtime", "alpamon-lock-runtime.service")
	// Load the idle runtime unit so discovery includes it without starting it.
	run("/usr/bin/systemctl", "show", "alpamon-lock-runtime.service")
	run("/usr/bin/systemctl", "start", "alpamon-lock-listener.socket", "alpamon-lock-custom.socket")
	enablement := func() {
		assert.Equal(t, "enabled", run("/usr/bin/systemctl", "is-enabled", "alpamon-lock-root.service"))
		assert.Equal(t, "enabled-runtime", run("/usr/bin/systemctl", "is-enabled", "alpamon-lock-runtime.service"))
	}
	runtimeLink := "/run/systemd/system/multi-user.target.wants/alpamon-lock-runtime.service"
	linkBefore, err := os.Readlink(runtimeLink)
	require.NoError(t, err)
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	triggerTimer := func() { run("/usr/bin/systemctl", "restart", "alpamon-lock-foo.timer") }
	connect := func() {
		conn, err := net.DialTimeout("unix", socketPath, time.Second)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
	triggerTimer()
	require.Eventually(t, func() bool { return exists(foo) }, 3*time.Second, 10*time.Millisecond)
	connect()
	require.Eventually(t, func() bool { return exists(socketStarted) }, 3*time.Second, 10*time.Millisecond)
	// Wait for the successful oneshot before re-triggering it under the lock.
	require.Eventually(t, func() bool {
		return run("/usr/bin/systemctl", "show", "--property=ActiveState", "--value", "alpamon-lock-foo.service") == "inactive"
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, os.Remove(foo))
	require.NoError(t, os.Remove(socketStarted))
	h := userhandler.NewUserHandler(executor.NewExecutor(), nil, nil)
	change := func(command string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		code, output, err := h.Execute(ctx, command, &common.CommandArgs{Username: name})
		require.NoError(t, err)
		require.Zero(t, code, output)
		t.Log(output)
	}
	enablement()
	run("/usr/bin/systemctl", "stop", "alpamon-lock-foo.timer")
	change("lockuser")
	enablement()
	require.NoError(t, os.Chmod(home, 0755))
	triggerTimer()
	require.Eventually(t, func() bool {
		return run("/usr/bin/systemctl", "show", "--property=ConditionResult", "--value", "alpamon-lock-foo.service") == "no"
	}, 3*time.Second, 10*time.Millisecond)
	connect()
	customConn, err := net.DialTimeout("unix", "/run/alpamon-lock-custom.sock", time.Second)
	require.NoError(t, err)
	require.NoError(t, customConn.Close())
	assert.Never(t, func() bool { return exists(foo) || exists(socketStarted) || exists(customStarted) }, 500*time.Millisecond, 10*time.Millisecond)
	run("/usr/bin/systemctl", "stop", "alpamon-lock-foo.timer")
	change("unlockuser")
	enablement()
	linkAfter, err := os.Readlink(runtimeLink)
	require.NoError(t, err)
	assert.Equal(t, linkBefore, linkAfter)
	assert.Never(t, func() bool { return exists(foo) || exists(socketStarted) || exists(customStarted) }, 300*time.Millisecond, 10*time.Millisecond)
	assert.Equal(t, "inactive", run("/usr/bin/systemctl", "show", "--property=ActiveState", "--value", "alpamon-lock-runtime.service"))
	triggerTimer()
	require.Eventually(t, func() bool { return exists(foo) }, 3*time.Second, 10*time.Millisecond)
	t.Log("timer blocked while locked and ran after unlock; Accept=yes socket blocked; Also= root unit and enabled-runtime preserved; unlock started nothing")
	// The runner destroys this container, including all fixture users and units.
	for _, root := range []string{"/run/systemd/system", "/etc/systemd/system"} {
		for _, unit := range []string{"alpamon-lock-foo.service", "alpamon-lock-listener@.service", "alpamon-lock-custom-worker@.service", "alpamon-lock-runtime.service"} {
			_, err := os.Stat(filepath.Join(root, unit+".d", "zz-alpamon-user-lock.conf"))
			assert.ErrorIs(t, err, os.ErrNotExist, fmt.Sprint(root, unit))
		}
	}
	changeAccount := func(command, username string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		code, output, err := h.Execute(ctx, command, &common.CommandArgs{Username: username})
		require.NoError(t, err)
		require.Zero(t, code, output)
		return output
	}
	property := func(unit, key string) string {
		return run("/usr/bin/systemctl", "show", "--property="+key, "--value", unit)
	}
	t.Run("lingering instances", func(t *testing.T) {
		var managers []string
		for _, username := range []string{"alice", "bob"} {
			run("/usr/sbin/useradd", "-m", "-s", "/bin/sh", username)
			run("/usr/sbin/usermod", "-p", "synthetic-test-hash", username)
			run("/usr/bin/loginctl", "enable-linger", username)
			managers = append(managers, "user@"+run("/usr/bin/id", "-u", username)+".service")
		}
		run("/usr/bin/loginctl", "enable-linger", "root")
		managers = append(managers, "user@0.service")
		for _, unit := range managers {
			require.Eventually(t, func() bool { return property(unit, "ActiveState") == "active" }, 5*time.Second, 50*time.Millisecond)
		}
		changeAccount("lockuser", "alice")
		for _, root := range []string{"/run/systemd/system", "/etc/systemd/system"} {
			assert.FileExists(t, filepath.Join(root, managers[0]+".d", "zz-alpamon-user-lock.conf"))
			_, err := os.Stat(filepath.Join(root, "user@.service.d", "zz-alpamon-user-lock.conf"))
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
		for _, unit := range managers[1:] {
			assert.Equal(t, "active", property(unit, "ActiveState"))
			run("/usr/bin/systemctl", "restart", unit)
			assert.Equal(t, "active", property(unit, "ActiveState"))
			assert.Equal(t, "yes", property(unit, "ConditionResult"))
		}
		changeAccount("lockuser", "bob")
		assert.Equal(t, "active", property(managers[2], "ActiveState"))
		changeAccount("unlockuser", "alice")
		changeAccount("unlockuser", "bob")
		t.Log("locking alice left bob and root user@ instances active and restartable; locking bob afterwards succeeded")
	})
	t.Run("trigger recovery", func(t *testing.T) {
		socket := "alpamon-lock-recover.socket"
		path := "alpamon-lock-recover.path"
		socketFile := "/run/alpamon-lock-recover.sock"
		pathFile := "/run/alpamon-lock-recover-event"
		services := []string{"alpamon-lock-socket-worker.service", "alpamon-lock-path-worker.service"}
		fixtures := map[string]string{
			socket: "[Socket]\nListenStream=" + socketFile + "\nAccept=no\nService=" + services[0] + "\nTriggerLimitIntervalSec=10s\nTriggerLimitBurst=2\n",
			path:   "[Path]\nPathExists=" + pathFile + "\nUnit=" + services[1] + "\nTriggerLimitIntervalSec=10s\nTriggerLimitBurst=2\n",
		}
		for _, service := range services {
			fixtures[service] = "[Service]\nUser=" + name + "\nExecStart=/usr/bin/sleep infinity\n"
			// The lock condition must sort after a conventional condition reset.
			dir := filepath.Join("/etc/systemd/system", service+".d")
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "override.conf"), []byte("[Unit]\nConditionPathExists=\n"), 0644))
		}
		for unit, body := range fixtures {
			require.NoError(t, os.WriteFile(filepath.Join("/etc/systemd/system", unit), []byte(body), 0644))
		}
		run("/usr/bin/systemctl", "daemon-reload")
		run("/usr/bin/systemctl", "start", socket, path)
		changeAccount("lockuser", name)
		conn, err := net.DialTimeout("unix", socketFile, time.Second)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(pathFile, nil, 0600))
		for _, unit := range []string{socket, path} {
			require.Eventually(t, func() bool { return property(unit, "Result") == "trigger-limit-hit" }, 5*time.Second, 50*time.Millisecond)
		}
		require.NoError(t, conn.Close())
		require.NoError(t, os.Remove(pathFile))
		output := changeAccount("unlockuser", name)
		assert.NotContains(t, output, "triggers_not_restored")
		for _, unit := range []string{socket, path} {
			assert.Equal(t, "active", property(unit, "ActiveState"))
		}
		for _, service := range services {
			assert.Equal(t, "inactive", property(service, "ActiveState"))
		}
		conn, err = net.DialTimeout("unix", socketFile, time.Second)
		require.NoError(t, err)
		defer func() { assert.NoError(t, conn.Close()) }()
		require.NoError(t, os.WriteFile(pathFile, nil, 0600))
		for _, service := range services {
			require.Eventually(t, func() bool { return property(service, "ActiveState") == "active" }, 3*time.Second, 50*time.Millisecond)
		}
		t.Log("Accept=no socket and path reached trigger-limit-hit while locked; unlock restored both to active and services stayed inactive until the next trigger")
	})

}
