package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEditorTunnelSupported(t *testing.T) {
	assert.False(t, editorTunnelSupported("windows"))
	assert.True(t, editorTunnelSupported("linux"))
	assert.True(t, editorTunnelSupported("darwin"))
}

func TestTunnelHandler_ValidateClientTypeRequirements(t *testing.T) {
	h := NewTunnelHandler(common.NewMockCommandExecutor(t))
	h.demote = func(string, string, utils.DemoteOptions) (*utils.DemoteResult, error) { return nil, nil }
	data := OpenTunnelData{SessionID: "s1", URL: "wss://tunnel.example.com", ClientType: runner.ClientTypeEditor, Username: "u", Groupname: "g"}

	if runtime.GOOS == "windows" {
		err := h.validateClientTypeRequirements(runner.ClientTypeEditor, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "editor tunnel is not supported on "+runtime.GOOS)
	} else {
		assert.NoError(t, h.validateClientTypeRequirements(runner.ClientTypeEditor, data))
	}
}

func TestTunnelHandler_Validate(t *testing.T) {
	handler := NewTunnelHandler(common.NewMockCommandExecutor(t))
	handler.demote = func(_, groupname string, _ utils.DemoteOptions) (*utils.DemoteResult, error) {
		if groupname == "" {
			return nil, fmt.Errorf("groupname is required")
		}
		return nil, nil
	}

	tests := []struct {
		name    string
		cmd     string
		args    *common.CommandArgs
		wantErr bool
	}{
		{
			name: "opentunnel cli valid",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session123",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 8080,
			},
			wantErr: false,
		},
		{
			name: "opentunnel web valid",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session456",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeWeb,
				TargetPort: 3000,
			},
			wantErr: false,
		},
		{
			name: "opentunnel editor valid",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session789",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeEditor,
				Username:   "testuser",
				Groupname:  "testgroup",
			},
			wantErr: runtime.GOOS == "windows",
		},
		{
			name: "opentunnel editor missing groupname",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session101",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeEditor,
				Username:   "testuser",
			},
			wantErr: runtime.GOOS == "linux" || runtime.GOOS == "windows",
		},
		{
			name: "opentunnel cli missing target port",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session202",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
			},
			wantErr: true,
		},
		{
			name: "opentunnel cli invalid port zero",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session303",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 0,
			},
			wantErr: true,
		},
		{
			name: "opentunnel cli invalid port out of range",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session404",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 70000,
			},
			wantErr: true,
		},
		{
			name: "opentunnel editor missing username",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session505",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeEditor,
			},
			wantErr: true,
		},
		{
			name: "opentunnel invalid client type",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session606",
				URL:        "wss://tunnel.example.com",
				ClientType: "invalid",
				TargetPort: 8080,
			},
			wantErr: true,
		},
		{
			name: "opentunnel default client type (backward compat)",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session707",
				URL:        "wss://tunnel.example.com",
				TargetPort: 8080,
				// ClientType is empty - should default to cli
			},
			wantErr: false,
		},
		{
			name: "opentunnel missing session ID",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 8080,
			},
			wantErr: true,
		},
		{
			name: "opentunnel missing URL",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session808",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 8080,
			},
			wantErr: true,
		},
		{
			name: "opentunnel invalid session ID traversal",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "../session",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 8080,
			},
			wantErr: true,
		},
		{
			name: "opentunnel invalid session ID with slash",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session/123",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeCLI,
				TargetPort: 8080,
			},
			wantErr: true,
		},
		{
			name: "closetunnel valid",
			cmd:  "closetunnel",
			args: &common.CommandArgs{
				SessionID: "session909",
			},
			wantErr: false,
		},
		{
			name: "closetunnel invalid session ID",
			cmd:  "closetunnel",
			args: &common.CommandArgs{
				SessionID: "session/909",
			},
			wantErr: true,
		},
		{
			name:    "closetunnel missing session ID",
			cmd:     "closetunnel",
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

func TestTunnelHandler_Commands(t *testing.T) {
	handler := NewTunnelHandler(common.NewMockCommandExecutor(t))

	commands := handler.Commands()
	assert.ElementsMatch(t, []string{"opentunnel", "closetunnel"}, commands)
}

func TestTunnelHandler_EditorValidatesGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("editor group validation applies on Linux")
	}
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
			h := NewTunnelHandler(common.NewMockCommandExecutor(t))
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
			args := &common.CommandArgs{SessionID: "editor-group-test", URL: "wss://example.com/tunnel", ClientType: runner.ClientTypeEditor, Username: "member", Groupname: tt.groupname}
			if tt.wantError == "" {
				require.NoError(t, h.Validate("opentunnel", args))
			} else {
				code, output, err := h.Execute(context.Background(), "opentunnel", args)
				require.NoError(t, err)
				assert.Equal(t, 1, code)
				assert.Contains(t, output, tt.wantError)
			}
			if tt.groupname != "" {
				assert.True(t, called, "the operation must validate the requested identity")
			}
		})
	}
}

func TestTunnelHandler_DarwinEditorSkipsGroupValidation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS editor behavior")
	}
	for _, groupname := range []string{"alpacon", "account", ""} {
		t.Run(groupname, func(t *testing.T) {
			h := NewTunnelHandler(common.NewMockCommandExecutor(t))
			h.demote = func(string, string, utils.DemoteOptions) (*utils.DemoteResult, error) {
				t.Fatal("macOS editor must not look up the requested identity")
				return nil, nil
			}
			args := &common.CommandArgs{SessionID: "editor-group-test", URL: "wss://example.com/tunnel", ClientType: runner.ClientTypeEditor, Username: "account", Groupname: groupname}
			require.NoError(t, h.Validate("opentunnel", args))
		})
	}
}

// setServerURL makes serverURL the configured Alpacon server, which is the only
// host a tunnel URL may name.
func setServerURL(t *testing.T, serverURL string) {
	t.Helper()
	prev := config.GlobalSettings.ServerURL
	config.GlobalSettings.ServerURL = serverURL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prev })
}

func TestOpenTunnel_ReportsATunnelServerThatRefusesTheDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	setServerURL(t, srv.URL)
	h := NewTunnelHandler(common.NewMockCommandExecutor(t))
	h.checkResources = func() error { return nil }
	args := &common.CommandArgs{
		SessionID:  "refused-dial",
		URL:        "/ws/tunnel/refused-dial/",
		ClientType: runner.ClientTypeCLI,
		TargetPort: 8080,
	}

	exitCode, result, err := h.Execute(t.Context(), common.OpenTunnel.String(), args)

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "opentunnel: failed to connect to tunnel server: websocket: bad handshake (HTTP 403)", result)
	_, registered := runner.GetActiveTunnel(args.SessionID)
	assert.False(t, registered)
}

func TestOpenTunnel_ReportsAnEditorWhoseCodeServerCannotBePrepared(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux resolves the editor user when the code-server manager is created")
	}
	h := NewTunnelHandler(common.NewMockCommandExecutor(t))
	h.checkResources = func() error { return nil }
	h.demote = func(string, string, utils.DemoteOptions) (*utils.DemoteResult, error) { return nil, nil }
	args := &common.CommandArgs{
		SessionID:  "editor-no-user",
		URL:        "/ws/tunnel/editor-no-user/",
		ClientType: runner.ClientTypeEditor,
		Username:   "alpamon-test-no-such-user",
		Groupname:  "alpamon-test-no-such-group",
	}

	exitCode, result, err := h.Execute(t.Context(), common.OpenTunnel.String(), args)

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, result, "opentunnel: failed to create code-server manager: ")
	_, registered := runner.GetActiveTunnel(args.SessionID)
	assert.False(t, registered)
}

func TestOpenTunnel_RefusesWhenResourcesAreExhausted(t *testing.T) {
	h := NewTunnelHandler(common.NewMockCommandExecutor(t))
	h.checkResources = func() error { return errors.New("CPU usage 100.0% exceeds limit 90%") }
	args := &common.CommandArgs{
		SessionID:  "busy-host",
		URL:        "/ws/tunnel/busy-host/",
		ClientType: runner.ClientTypeCLI,
		TargetPort: 8080,
	}

	exitCode, result, err := h.Execute(t.Context(), common.OpenTunnel.String(), args)

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "opentunnel: CPU usage 100.0% exceeds limit 90%", result)
	_, registered := runner.GetActiveTunnel(args.SessionID)
	assert.False(t, registered)
}
