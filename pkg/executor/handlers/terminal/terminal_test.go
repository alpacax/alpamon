package terminal

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalHandler_Validate(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager(nil))

	tests := []struct {
		name    string
		cmd     string
		args    *common.CommandArgs
		wantErr bool
	}{
		{
			name: "openpty valid",
			cmd:  "openpty",
			args: &common.CommandArgs{
				SessionID:     "session123",
				URL:           "ws://localhost:8080",
				Username:      "testuser",
				Groupname:     "testgroup",
				HomeDirectory: "/home/testuser",
				Rows:          24,
				Cols:          80,
			},
			wantErr: false,
		},
		{
			name: "openpty missing required fields",
			cmd:  "openpty",
			args: &common.CommandArgs{
				SessionID: "session123",
				// Missing URL and Username
			},
			wantErr: true,
		},
		{
			name: "openftp valid",
			cmd:  "openftp",
			args: &common.CommandArgs{
				SessionID: "ftp123",
				URL:       "ftp://localhost",
				Username:  "testuser",
			},
			wantErr: false,
		},
		{
			name: "openftp missing username",
			cmd:  "openftp",
			args: &common.CommandArgs{
				SessionID: "ftp123",
				URL:       "ftp://localhost",
			},
			wantErr: true,
		},
		{
			name: "resizepty valid",
			cmd:  "resizepty",
			args: &common.CommandArgs{
				SessionID: "session123",
				Rows:      40,
				Cols:      120,
			},
			wantErr: false,
		},
		{
			name: "resizepty missing session ID",
			cmd:  "resizepty",
			args: &common.CommandArgs{
				Rows: 40,
				Cols: 120,
			},
			wantErr: true,
		},
		{
			name: "refreshpty valid",
			cmd:  "refreshpty",
			args: &common.CommandArgs{
				SessionID: "session123",
			},
			wantErr: false,
		},
		{
			name:    "refreshpty missing session ID",
			cmd:     "refreshpty",
			args:    &common.CommandArgs{},
			wantErr: true,
		},
		{
			name:    "unknown command",
			cmd:     "unknown",
			args:    &common.CommandArgs{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.Validate(tt.cmd, tt.args)
			assert.Equal(t, tt.wantErr, err != nil, "Validate() error = %v", err)
		})
	}
}

func TestTerminalHandler_Execute_UnknownCommand(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager(nil))

	exitCode, _, err := handler.Execute(context.TODO(), "unknown", &common.CommandArgs{})

	assert.Error(t, err, "Execute() expected error for unknown command")
	assert.Equal(t, 1, exitCode)
}

func TestTerminalHandler_RefreshPTY_InvalidSession(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager(nil))

	args := &common.CommandArgs{
		SessionID: "nonexistent",
	}

	exitCode, output, err := handler.Execute(context.TODO(), "refreshpty", args)

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "invalid session ID", output)
}

func TestTerminalHandler_ResizePTY_InvalidSession(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager(nil))

	args := &common.CommandArgs{
		SessionID: "nonexistent",
		Rows:      40,
		Cols:      120,
	}

	exitCode, output, err := handler.Execute(context.TODO(), "resizepty", args)

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "invalid session ID", output)
}

func TestTerminalHandler_OpenFTPValidatesGroup(t *testing.T) {
	previousCA := config.GlobalSettings.CaCert
	config.GlobalSettings.CaCert = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() { config.GlobalSettings.CaCert = previousCA })
	tests := []struct {
		name      string
		groupname string
		wantError string
	}{
		{name: "primary group", groupname: "primary"},
		{name: "supplementary group", groupname: "shared"},
		{name: "non-member group", groupname: "other", wantError: "groupname other is not in user member's group list"},
		{name: "unknown group", groupname: "unknown", wantError: "there is no corresponding unknown groupname in this server"},
		{name: "empty group", wantError: "groupname is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager(nil))
			called := false
			h.demote = func(username, groupname string, opts utils.DemoteOptions) (*utils.DemoteResult, error) {
				called = true
				assert.Equal(t, "member", username)
				assert.Equal(t, tt.groupname, groupname)
				assert.True(t, opts.ValidateGroup)
				if tt.wantError != "" {
					return nil, fmt.Errorf("%s", tt.wantError)
				}
				usr, err := common.ExistingUserLookup("1001")(username)
				require.NoError(t, err)
				return &utils.DemoteResult{User: usr}, nil
			}
			args := &common.CommandArgs{SessionID: "ftp-group-test", URL: "wss://example.com/ftp", Username: "member", Groupname: tt.groupname}
			code, output, err := h.Execute(context.Background(), "openftp", args)
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			if tt.wantError == "" {
				assert.Contains(t, output, "Failed to prepare connection settings", "an accepted group must reach worker setup")
			} else {
				assert.Contains(t, output, tt.wantError)
			}
			if tt.groupname != "" {
				assert.True(t, called, "the operation must validate the requested identity")
			}
		})
	}
}

func TestFTPWorkerEnvironment(t *testing.T) {
	t.Setenv("PLUGIN_KEY", "synthetic-value")
	t.Setenv("HTTP_PROXY", "http://review:synthetic-value@proxy.invalid")
	t.Setenv("HOME", "/agent")
	t.Setenv("LC_TIME", "C")
	t.Setenv("SSL_CERT_FILE", "/agent/roots.pem")
	t.Setenv("SSL_CERT_DIR", "/agent/roots:/other/roots")
	t.Setenv("UNRELATED_SETTING", "excluded")
	cmd := ftpWorkerCommand("/bin/sh", "/home/session", "session", []string{"-c", `printf '%s|%s|%s|%s|%s' "$HOME" "$USER" "$LOGNAME" "$LC_TIME" "$PLUGIN_KEY"`})
	if runtime.GOOS == "windows" {
		assert.Contains(t, cmd.Env, "HOME=/agent")
		assert.Contains(t, cmd.Env, "HTTP_PROXY=http://review:synthetic-value@proxy.invalid")
		for _, entry := range cmd.Env {
			assert.False(t, strings.HasPrefix(strings.ToUpper(entry), "PLUGIN_"))
		}
		return
	}
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		assert.True(t, key == "SSL_CERT_FILE" || key == "SSL_CERT_DIR" || key == "HOME" || key == "USER" || key == "LOGNAME" || key == "PATH" || key == "LANG" || strings.HasPrefix(key, "LC_"), "unexpected variable %s", key)
	}
	assert.Contains(t, cmd.Env, "SSL_CERT_FILE=/agent/roots.pem")
	assert.Contains(t, cmd.Env, "SSL_CERT_DIR=/agent/roots:/other/roots")
	assert.Contains(t, cmd.Env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	output, err := cmd.Output()
	require.NoError(t, err)
	assert.Equal(t, "/home/session|session|session|C|", string(output))
}
