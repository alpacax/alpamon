package terminal

import (
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

func TestTerminalHandler_Validate(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil)

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

func TestTerminalHandler_Execute_UnknownCommand(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil)

	exitCode, _, err := handler.Execute(nil, "unknown", &common.CommandArgs{})

	if err == nil {
		t.Error("Execute() expected error for unknown command")
	}
	if exitCode != 1 {
		t.Errorf("Execute() exitCode = %v, want 1", exitCode)
	}
}

func TestTerminalHandler_ResizePTY_InvalidSession(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil)

	args := &common.CommandArgs{
		SessionID: "nonexistent",
		Rows:      40,
		Cols:      120,
	}

	exitCode, output, err := handler.Execute(nil, "resizepty", args)

	if err != nil {
		t.Errorf("Execute() unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("Execute() exitCode = %v, want 1", exitCode)
	}
	if output != "Invalid session ID" {
		t.Errorf("Execute() output = %v, want 'Invalid session ID'", output)
	}
}
