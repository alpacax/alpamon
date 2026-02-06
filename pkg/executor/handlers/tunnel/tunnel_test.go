package tunnel

import (
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/runner"
)

func TestTunnelHandler_Validate(t *testing.T) {
	handler := NewTunnelHandler(common.NewMockCommandExecutor(t))

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
			wantErr: false,
		},
		{
			name: "opentunnel editor valid without groupname",
			cmd:  "opentunnel",
			args: &common.CommandArgs{
				SessionID:  "session101",
				URL:        "wss://tunnel.example.com",
				ClientType: runner.ClientTypeEditor,
				Username:   "testuser",
			},
			wantErr: false,
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
			name: "closetunnel valid",
			cmd:  "closetunnel",
			args: &common.CommandArgs{
				SessionID: "session909",
			},
			wantErr: false,
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
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTunnelHandler_Commands(t *testing.T) {
	handler := NewTunnelHandler(common.NewMockCommandExecutor(t))

	commands := handler.Commands()
	if len(commands) != 2 {
		t.Errorf("Commands() returned %d commands, want 2", len(commands))
	}

	expectedCmds := map[string]bool{
		"opentunnel":  false,
		"closetunnel": false,
	}

	for _, cmd := range commands {
		if _, ok := expectedCmds[cmd]; ok {
			expectedCmds[cmd] = true
		} else {
			t.Errorf("Unexpected command: %s", cmd)
		}
	}

	for cmd, found := range expectedCmds {
		if !found {
			t.Errorf("Expected command not found: %s", cmd)
		}
	}
}
