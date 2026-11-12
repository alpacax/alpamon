//go:build linux && integration

package user_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	userhandler "github.com/alpacax/alpamon/v2/pkg/executor/handlers/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountLockIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated Docker container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("requires an isolated Docker container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := executor.NewExecutor()
	name := fmt.Sprintf("alpamon-lock-%d", os.Getpid())
	code, output, err := runner.Run(ctx, "/usr/sbin/useradd", "-m", "-U", "-s", "/bin/sh", "-e", "21000", "--", name)
	require.NoError(t, err, output)
	require.Zero(t, code, output)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _, cleanupErr := runner.Run(cleanupCtx, "/usr/sbin/userdel", "-r", "--", name)
		assert.NoError(t, cleanupErr)
	})
	// A non-authenticating synthetic hash exercises an initially unlocked field.
	code, output, err = runner.Run(ctx, "/usr/sbin/usermod", "-p", "synthetic-test-hash", "--", name)
	require.NoError(t, err, output)
	require.Zero(t, code, output)
	account, err := user.Lookup(name)
	require.NoError(t, err)
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	require.NoError(t, err)
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	require.NoError(t, err)
	sentinel := filepath.Join(account.HomeDir, "retained")
	require.NoError(t, os.WriteFile(sentinel, []byte("retained"), 0600))
	child := exec.Command("/usr/bin/sleep", "60")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	require.NoError(t, child.Start())
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()

	h := userhandler.NewUserHandler(runner, nil, nil)
	args := &common.CommandArgs{Username: name, UID: uid, UIDPresent: true}
	code, output, err = h.Execute(ctx, "lockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	var locked struct {
		ProcessesEnded int `json:"processes_ended"`
	}
	require.NoError(t, json.Unmarshal([]byte(output), &locked))
	assert.Equal(t, 1, locked.ProcessesEnded)
	require.Error(t, child.Wait())
	waited = true
	code, output, err = runner.Run(ctx, "/usr/bin/passwd", "-S", name)
	require.NoError(t, err, output)
	require.Zero(t, code)
	assert.Equal(t, "L", strings.Fields(output)[1])
	code, output, err = runner.Run(ctx, "/usr/bin/chage", "-l", name)
	require.NoError(t, err, output)
	require.Zero(t, code)
	assert.Contains(t, output, "Jan 02, 1970")
	code, output, _ = runner.Run(ctx, "/usr/bin/pgrep", "-u", account.Uid)
	assert.Equal(t, 1, code, output)
	_, err = user.Lookup(name)
	require.NoError(t, err)
	assert.DirExists(t, account.HomeDir)
	contents, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	assert.Equal(t, "retained", string(contents))

	code, output, err = h.Execute(ctx, "unlockuser", args)
	require.NoError(t, err)
	require.Zero(t, code, output)
	assert.Equal(t, fmt.Sprintf(`{"username":%q,"locked":false,"already_unlocked":false}`, name), output)
	code, output, err = runner.Run(ctx, "/usr/bin/passwd", "-S", name)
	require.NoError(t, err, output)
	require.Zero(t, code)
	assert.Equal(t, "P", strings.Fields(output)[1])
	code, output, err = runner.Run(ctx, "/usr/bin/chage", "-l", name)
	require.NoError(t, err, output)
	require.Zero(t, code)
	assert.NotContains(t, output, "Jan 02, 1970")
	code, output, _ = runner.Run(ctx, "/usr/bin/pgrep", "-u", account.Uid)
	assert.Equal(t, 1, code, output)
}
