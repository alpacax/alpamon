package firewall

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// FirewallHandler handles firewall management commands
// Note: This is a basic extraction from command.go. Full refactoring scheduled for Phase 3.
type FirewallHandler struct {
	*common.BaseHandler
}

// NewFirewallHandler creates a new firewall handler
func NewFirewallHandler(cmdExecutor common.CommandExecutor) *FirewallHandler {
	h := &FirewallHandler{
		BaseHandler: common.NewBaseHandler(
			common.Firewall,
			[]common.CommandType{
				common.FirewallCmd,
				common.FirewallRollback,
				common.FirewallReorderChains,
				common.FirewallReorderRules,
			},
			cmdExecutor,
		),
	}
	return h
}

// Execute runs the firewall management command
func (h *FirewallHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	// Check if firewall is disabled
	if utils.IsFirewallDisabled() {
		log.Warn().Msg("Firewall command ignored - firewall functionality is temporarily disabled")
		return 0, "Firewall functionality is temporarily disabled", nil
	}

	// Check for high-level firewall tools
	if detected, toolName := utils.DetectHighLevelFirewall(); detected {
		return 1, fmt.Sprintf("Alpacon firewall management is disabled because %s is active. Please use %s to manage firewall rules.",
			toolName, toolName), nil
	}

	switch cmd {
	case common.FirewallCmd.String():
		return h.handleFirewall(args)
	case common.FirewallRollback.String():
		return h.handleFirewallRollback()
	case common.FirewallReorderChains.String():
		return h.handleFirewallReorderChains(args)
	case common.FirewallReorderRules.String():
		return h.handleFirewallReorderRules(args)
	default:
		return 1, "", fmt.Errorf("unknown firewall command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *FirewallHandler) Validate(cmd string, args *common.CommandArgs) error {
	switch cmd {
	case common.FirewallCmd.String():
		operation := args.Operation
		if operation == "" {
			return fmt.Errorf("firewall: operation is required")
		}
		// Additional validation based on operation type
		switch operation {
		case common.FirewallOpBatch, common.FirewallOpFlush, common.FirewallOpDelete, common.FirewallOpAdd, common.FirewallOpUpdate:
			// Each operation has specific validation requirements
			// For now, basic validation only
			return nil
		default:
			return fmt.Errorf("firewall: unknown operation '%s'", operation)
		}

	case common.FirewallRollback.String():
		// No specific validation needed
		return nil

	case common.FirewallReorderChains.String():
		chainNames := args.ChainNames
		if len(chainNames) == 0 {
			return fmt.Errorf("firewall-reorder-chains: chain names are required")
		}
		return nil

	case common.FirewallReorderRules.String():
		chainName := args.ChainName
		if chainName == "" {
			return fmt.Errorf("firewall-reorder-rules: chain name is required")
		}
		return nil

	default:
		return fmt.Errorf("unknown firewall command: %s", cmd)
	}
}

// handleFirewall handles the main firewall command
func (h *FirewallHandler) handleFirewall(args *common.CommandArgs) (int, string, error) {
	operation := args.Operation

	log.Info().
		Str("operation", operation).
		Msg("Executing firewall operation")

	switch operation {
	case common.FirewallOpBatch:
		return h.handleBatchOperation(args)
	case common.FirewallOpFlush:
		return h.handleFlushOperation(args)
	case common.FirewallOpDelete:
		return h.handleDeleteOperation(args)
	case common.FirewallOpAdd:
		return h.handleAddOperation(args)
	case common.FirewallOpUpdate:
		return h.handleUpdateOperation(args)
	default:
		return 1, fmt.Sprintf("firewall: Unknown operation '%s'", operation), nil
	}
}

// handleBatchOperation handles batch firewall operations
func (h *FirewallHandler) handleBatchOperation(args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName
	rules := args.Rules

	log.Info().
		Str("chain", chainName).
		Int("ruleCount", len(rules)).
		Msg("Firewall batch operation")

	if len(rules) == 0 {
		return 0, `{"success": true, "applied_rules": 0, "failed_rules": [], "rolled_back": false, "message": "No rules to apply"}`, nil
	}

	// TODO: Implement actual batch operation logic
	// This is a placeholder for Phase 3 implementation
	result := map[string]interface{}{
		"success":       true,
		"applied_rules": len(rules),
		"failed_rules":  []interface{}{},
		"rolled_back":   false,
		"message":       "Batch operation placeholder - full implementation in Phase 3",
	}

	resultJSON, _ := json.Marshal(result)
	return 0, string(resultJSON), nil
}

// handleFlushOperation handles flush firewall operations
func (h *FirewallHandler) handleFlushOperation(args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName

	log.Info().
		Str("chain", chainName).
		Msg("Firewall flush operation")

	// TODO: Implement actual flush operation logic
	// This is a placeholder for Phase 3 implementation
	return 0, fmt.Sprintf("Chain '%s' flush operation placeholder - full implementation in Phase 3", chainName), nil
}

// handleDeleteOperation handles delete firewall operations
func (h *FirewallHandler) handleDeleteOperation(args *common.CommandArgs) (int, string, error) {
	ruleID := args.RuleID

	log.Info().
		Str("ruleID", ruleID).
		Msg("Firewall delete operation")

	// TODO: Implement actual delete operation logic
	// This is a placeholder for Phase 3 implementation
	return 0, fmt.Sprintf("Rule '%s' delete operation placeholder - full implementation in Phase 3", ruleID), nil
}

// handleAddOperation handles add firewall operations
func (h *FirewallHandler) handleAddOperation(args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName

	log.Info().
		Str("chain", chainName).
		Msg("Firewall add operation")

	// TODO: Implement actual add operation logic
	// This is a placeholder for Phase 3 implementation
	return 0, "Firewall add operation placeholder - full implementation in Phase 3", nil
}

// handleUpdateOperation handles update firewall operations
func (h *FirewallHandler) handleUpdateOperation(args *common.CommandArgs) (int, string, error) {
	ruleID := args.RuleID
	oldRuleID := args.OldRuleID

	log.Info().
		Str("ruleID", ruleID).
		Str("oldRuleID", oldRuleID).
		Msg("Firewall update operation")

	// TODO: Implement actual update operation logic
	// This is a placeholder for Phase 3 implementation
	return 0, "Firewall update operation placeholder - full implementation in Phase 3", nil
}

// handleFirewallRollback handles firewall rollback command
func (h *FirewallHandler) handleFirewallRollback() (int, string, error) {
	log.Info().Msg("Executing firewall rollback")

	// Use utils package to restore firewall rules
	err := utils.RestoreFirewallRules("")
	if err != nil {
		return 1, fmt.Sprintf("Failed to rollback firewall: %v", err), err
	}

	return 0, "Firewall rules rolled back successfully", nil
}

// handleFirewallReorderChains handles firewall chain reordering
func (h *FirewallHandler) handleFirewallReorderChains(args *common.CommandArgs) (int, string, error) {
	chainNames := args.ChainNames

	log.Info().
		Strs("chains", chainNames).
		Msg("Reordering firewall chains")

	// TODO: Implement actual chain reordering logic
	// This is a placeholder for Phase 3 implementation
	return 0, fmt.Sprintf("Chain reorder operation placeholder for chains: %v", chainNames), nil
}

// handleFirewallReorderRules handles firewall rule reordering within a chain
func (h *FirewallHandler) handleFirewallReorderRules(args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName
	rules := args.Rules

	log.Info().
		Str("chain", chainName).
		Int("ruleCount", len(rules)).
		Msg("Reordering firewall rules")

	// TODO: Implement actual rule reordering logic
	// This is a placeholder for Phase 3 implementation
	return 0, fmt.Sprintf("Rule reorder operation placeholder for chain '%s'", chainName), nil
}
