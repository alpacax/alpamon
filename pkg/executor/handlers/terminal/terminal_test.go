package terminal

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/stretchr/testify/assert"
)

func TestTerminalHandler_Validate(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager())

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
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager())

	exitCode, _, err := handler.Execute(context.TODO(), "unknown", &common.CommandArgs{})

	assert.Error(t, err, "Execute() expected error for unknown command")
	assert.Equal(t, 1, exitCode)
}

func TestTerminalHandler_RefreshPTY_InvalidSession(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager())

	args := &common.CommandArgs{
		SessionID: "nonexistent",
	}

	exitCode, output, err := handler.Execute(context.TODO(), "refreshpty", args)

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "invalid session ID", output)
}

func TestTerminalHandler_ResizePTY_InvalidSession(t *testing.T) {
	handler := NewTerminalHandler(common.NewMockCommandExecutor(t), nil, runner.NewTerminalManager())

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
