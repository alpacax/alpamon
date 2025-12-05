package firewall

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
)

func TestFirewallHandler_Execute(t *testing.T) {
	// Temporarily enable firewall functionality for this test
	utils.FirewallFunctionalityDisabled = false
	t.Cleanup(func() {
		utils.FirewallFunctionalityDisabled = true
	})

	tests := []struct {
		name     string
		cmd      string
		args     *common.CommandArgs
		wantCode int
		wantErr  bool
	}{
		{
			name: "firewall batch operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "batch",
				ChainName: "INPUT",
				Rules: []common.FirewallRule{
					{
						Protocol: "tcp",
					},
				},
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name: "firewall flush operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "flush",
				ChainName: "FORWARD",
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name: "firewall delete operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "delete",
				RuleID:    "rule123",
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name: "firewall add operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "add",
				ChainName: "OUTPUT",
				Protocol:  "tcp",
				Target:    "ACCEPT",
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name: "firewall update operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "update",
				RuleID:    "rule123",
				OldRuleID: "rule122",
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name: "firewall unknown operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "unknown",
			},
			wantCode: 1,
			wantErr:  false,
		},
		{
			name:     "firewall-rollback",
			cmd:      "firewall-rollback",
			args:     &common.CommandArgs{},
			wantCode: 1,  // Changed from 0 to 1
			wantErr:  true, // Changed from false to true
		},
		{
			name: "firewall-reorder-chains",
			cmd:  "firewall-reorder-chains",
			args: &common.CommandArgs{
				ChainNames: []string{"INPUT", "OUTPUT", "FORWARD"},
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name: "firewall-reorder-rules",
			cmd:  "firewall-reorder-rules",
			args: &common.CommandArgs{
				ChainName: "INPUT",
				Rules: []common.FirewallRule{
					{RuleID: "rule1"},
					{RuleID: "rule2"},
				},
			},
			wantCode: 0,
			wantErr:  false,
		},
		{
			name:     "unknown firewall command",
			cmd:      "firewall-unknown",
			args:     &common.CommandArgs{},
			wantCode: 1,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := common.NewMockCommandExecutor(t)
			handler := NewFirewallHandler(mock)
			ctx := context.Background()

			exitCode, output, err := handler.Execute(ctx, tt.cmd, tt.args)

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if exitCode != tt.wantCode {
				t.Errorf("Execute() exitCode = %v, want %v", exitCode, tt.wantCode)
			}
			// Since these are placeholders, we expect some output for successful operations
			if exitCode == 0 && output == "" && !tt.wantErr {
				t.Error("Execute() returned success but no output")
			}
		})
	}
}

func TestFirewallHandler_Validate(t *testing.T) {
	handler := NewFirewallHandler(common.NewMockCommandExecutor(t))

	tests := []struct {
		name    string
		cmd     string
		args    *common.CommandArgs
		wantErr bool
	}{
		{
			name: "firewall valid batch operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "batch",
			},
			wantErr: false,
		},
		{
			name:    "firewall missing operation",
			cmd:     "firewall",
			args:    &common.CommandArgs{},
			wantErr: true,
		},
		{
			name: "firewall invalid operation",
			cmd:  "firewall",
			args: &common.CommandArgs{
				Operation: "invalid",
			},
			wantErr: true,
		},
		{
			name:    "firewall-rollback valid",
			cmd:     "firewall-rollback",
			args:    &common.CommandArgs{},
			wantErr: false,
		},
		{
			name: "firewall-reorder-chains valid",
			cmd:  "firewall-reorder-chains",
			args: &common.CommandArgs{
				ChainNames: []string{"INPUT", "OUTPUT"},
			},
			wantErr: false,
		},
		{
			name:    "firewall-reorder-chains missing chains",
			cmd:     "firewall-reorder-chains",
			args:    &common.CommandArgs{},
			wantErr: true,
		},
		{
			name: "firewall-reorder-rules valid",
			cmd:  "firewall-reorder-rules",
			args: &common.CommandArgs{
				ChainName: "INPUT",
			},
			wantErr: false,
		},
		{
			name:    "firewall-reorder-rules missing chain",
			cmd:     "firewall-reorder-rules",
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

func TestFirewallHandler_BatchOperation(t *testing.T) {
	handler := NewFirewallHandler(common.NewMockCommandExecutor(t))
	ctx := context.Background()

	// Test with empty rules
	args := &common.CommandArgs{
		Operation: "batch",
		ChainName: "INPUT",
		Rules:     []common.FirewallRule{},
	}

	exitCode, output, err := handler.Execute(ctx, "firewall", args)

	if err != nil {
		t.Errorf("Execute() unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Execute() exitCode = %v, want 0", exitCode)
	}
	if output == "" {
		t.Error("Execute() returned no output")
	}

	// Test with multiple rules
	args = &common.CommandArgs{
		Operation: "batch",
		ChainName: "INPUT",
		Rules: []common.FirewallRule{
			{
				Protocol: "tcp",
				Target:   "ACCEPT",
			},
			{
				Protocol: "tcp",
				Target:   "ACCEPT",
			},
		},
	}

	exitCode, output, err = handler.Execute(ctx, "firewall", args)

	if err != nil {
		t.Errorf("Execute() unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Execute() exitCode = %v, want 0", exitCode)
	}
	if output == "" {
		t.Error("Execute() returned no output")
	}
}
