package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/rs/zerolog/log"
)

// FirewallHandler handles firewall management commands
type FirewallHandler struct {
	*common.BaseHandler
	detector  *FirewallDetector
	backend   FirewallBackend
	backup    *BackupManager
	validator *Validator
	mu        sync.RWMutex
}

// NewFirewallHandler creates a new firewall handler
func NewFirewallHandler(cmdExecutor common.CommandExecutor) *FirewallHandler {
	detector := NewFirewallDetector(cmdExecutor)
	validator := NewValidator()

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
		detector:  detector,
		validator: validator,
	}
	return h
}

// initBackend initializes the firewall backend based on detection
func (h *FirewallHandler) initBackend(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.backend != nil {
		return nil
	}

	h.backend = h.detector.CreateBackend(ctx)
	if h.backend == nil {
		return fmt.Errorf("no firewall backend available")
	}

	h.backup = NewBackupManager(h.backend)
	log.Info().Str("backend", h.backend.Name()).Msg("Firewall backend initialized")
	return nil
}

// getBackend returns the current backend, initializing if needed
func (h *FirewallHandler) getBackend(ctx context.Context) (FirewallBackend, error) {
	h.mu.RLock()
	if h.backend != nil {
		defer h.mu.RUnlock()
		return h.backend, nil
	}
	h.mu.RUnlock()

	if err := h.initBackend(ctx); err != nil {
		return nil, err
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.backend, nil
}

// Execute runs the firewall management command
func (h *FirewallHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	// Check for high-level firewall tools
	result := h.detector.Detect(ctx)
	if result.HighLevel != HighLevelNone {
		return 1, fmt.Sprintf("Alpacon firewall management is disabled because %s is active. Please use %s to manage firewall rules.",
			result.HighLevel, result.HighLevel), nil
	}

	if result.Disabled {
		return 1, "Firewall functionality is not available - no backend detected", nil
	}

	// Initialize backend if not already done
	if _, err := h.getBackend(ctx); err != nil {
		return 1, fmt.Sprintf("Failed to initialize firewall: %v", err), err
	}

	switch cmd {
	case common.FirewallCmd.String():
		return h.handleFirewall(ctx, args)
	case common.FirewallRollback.String():
		return h.handleFirewallRollback(ctx)
	case common.FirewallReorderChains.String():
		return h.handleFirewallReorderChains(ctx, args)
	case common.FirewallReorderRules.String():
		return h.handleFirewallReorderRules(ctx, args)
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
		switch operation {
		case common.FirewallOpBatch:
			return h.validator.ValidateBatchRules(args.Rules)
		case common.FirewallOpFlush:
			if args.ChainName == "" {
				return fmt.Errorf("firewall flush: chain name is required")
			}
			return h.validator.ValidateChainName(args.ChainName)
		case common.FirewallOpDelete:
			if args.RuleID == "" {
				return fmt.Errorf("firewall delete: rule ID is required")
			}
			return nil
		case common.FirewallOpAdd:
			if len(args.Rules) == 0 {
				return fmt.Errorf("firewall add: at least one rule is required")
			}
			return h.validator.ValidateBatchRules(args.Rules)
		case common.FirewallOpUpdate:
			if args.RuleID == "" {
				return fmt.Errorf("firewall update: rule ID is required")
			}
			return nil
		default:
			return fmt.Errorf("firewall: unknown operation '%s'", operation)
		}

	case common.FirewallRollback.String():
		return nil

	case common.FirewallReorderChains.String():
		if len(args.ChainNames) == 0 {
			return fmt.Errorf("firewall-reorder-chains: chain names are required")
		}
		for _, name := range args.ChainNames {
			if err := h.validator.ValidateChainName(name); err != nil {
				return err
			}
		}
		return nil

	case common.FirewallReorderRules.String():
		if args.ChainName == "" {
			return fmt.Errorf("firewall-reorder-rules: chain name is required")
		}
		return h.validator.ValidateChainName(args.ChainName)

	default:
		return fmt.Errorf("unknown firewall command: %s", cmd)
	}
}

// handleFirewall handles the main firewall command
func (h *FirewallHandler) handleFirewall(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	operation := args.Operation

	log.Info().
		Str("operation", operation).
		Msg("Executing firewall operation")

	switch operation {
	case common.FirewallOpBatch:
		return h.handleBatchOperation(ctx, args)
	case common.FirewallOpFlush:
		return h.handleFlushOperation(ctx, args)
	case common.FirewallOpDelete:
		return h.handleDeleteOperation(ctx, args)
	case common.FirewallOpAdd:
		return h.handleAddOperation(ctx, args)
	case common.FirewallOpUpdate:
		return h.handleUpdateOperation(ctx, args)
	default:
		return 1, fmt.Sprintf("firewall: Unknown operation '%s'", operation), nil
	}
}

// handleBatchOperation handles batch firewall operations
func (h *FirewallHandler) handleBatchOperation(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName
	rules := args.Rules

	log.Info().
		Str("chain", chainName).
		Int("ruleCount", len(rules)).
		Msg("Firewall batch operation")

	if len(rules) == 0 {
		result := BatchResult{
			Success:      true,
			AppliedRules: 0,
			FailedRules:  []string{},
			RolledBack:   false,
			Message:      "No rules to apply",
		}
		resultJSON, _ := json.Marshal(result)
		return 0, string(resultJSON), nil
	}

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before batch operation
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before batch operation")
	}

	// Apply rules
	applied, failed, applyErr := backend.BatchApply(ctx, chainName, rules)

	result := BatchResult{
		Success:      applyErr == nil,
		AppliedRules: applied,
		FailedRules:  failed,
		RolledBack:   false,
	}

	// If there were failures and we have a backup, offer rollback info
	if applyErr != nil && h.backup.HasBackup() {
		result.Message = fmt.Sprintf("Batch operation completed with errors: %v. Rollback available.", applyErr)
	} else if applyErr != nil {
		result.Message = fmt.Sprintf("Batch operation completed with errors: %v", applyErr)
	} else {
		result.Message = fmt.Sprintf("Successfully applied %d rules", applied)
	}

	resultJSON, _ := json.Marshal(result)
	return 0, string(resultJSON), nil
}

// handleFlushOperation handles flush firewall operations
func (h *FirewallHandler) handleFlushOperation(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName

	log.Info().
		Str("chain", chainName).
		Msg("Firewall flush operation")

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before flush
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before flush operation")
	}

	if err := backend.FlushChain(ctx, chainName); err != nil {
		return 1, fmt.Sprintf("Failed to flush chain '%s': %v", chainName, err), err
	}

	return 0, fmt.Sprintf("Successfully flushed chain '%s'", chainName), nil
}

// handleDeleteOperation handles delete firewall operations
func (h *FirewallHandler) handleDeleteOperation(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	ruleID := args.RuleID
	chainName := args.ChainName

	log.Info().
		Str("ruleID", ruleID).
		Str("chain", chainName).
		Msg("Firewall delete operation")

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before delete
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before delete operation")
	}

	if err := backend.DeleteRule(ctx, ruleID, chainName); err != nil {
		return 1, fmt.Sprintf("Failed to delete rule '%s': %v", ruleID, err), err
	}

	return 0, fmt.Sprintf("Successfully deleted rule '%s'", ruleID), nil
}

// handleAddOperation handles add firewall operations
func (h *FirewallHandler) handleAddOperation(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName
	rules := args.Rules

	log.Info().
		Str("chain", chainName).
		Int("ruleCount", len(rules)).
		Msg("Firewall add operation")

	if len(rules) == 0 {
		return 0, "No rules to add", nil
	}

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before add
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before add operation")
	}

	// Add each rule
	var addedCount int
	var lastErr error
	for i, rule := range rules {
		ruleCopy := rule
		if ruleCopy.Chain == "" {
			ruleCopy.Chain = chainName
		}
		if err := backend.AddRule(ctx, &ruleCopy); err != nil {
			log.Error().Err(err).Int("ruleIndex", i).Msg("Failed to add rule")
			lastErr = err
			continue
		}
		addedCount++
	}

	if lastErr != nil {
		return 1, fmt.Sprintf("Added %d of %d rules, last error: %v", addedCount, len(rules), lastErr), lastErr
	}

	return 0, fmt.Sprintf("Successfully added %d rules", addedCount), nil
}

// handleUpdateOperation handles update firewall operations
func (h *FirewallHandler) handleUpdateOperation(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	ruleID := args.RuleID
	oldRuleID := args.OldRuleID
	chainName := args.ChainName

	log.Info().
		Str("ruleID", ruleID).
		Str("oldRuleID", oldRuleID).
		Str("chain", chainName).
		Msg("Firewall update operation")

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before update
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before update operation")
	}

	// Delete old rule if specified
	deleteID := oldRuleID
	if deleteID == "" {
		deleteID = ruleID
	}

	if deleteID != "" {
		if err := backend.DeleteRule(ctx, deleteID, chainName); err != nil {
			log.Warn().Err(err).Str("ruleID", deleteID).Msg("Failed to delete old rule during update")
		}
	}

	// Add new rule if provided
	if len(args.Rules) > 0 {
		rule := args.Rules[0]
		if rule.Chain == "" {
			rule.Chain = chainName
		}
		if err := backend.AddRule(ctx, &rule); err != nil {
			return 1, fmt.Sprintf("Failed to add updated rule: %v", err), err
		}
	}

	return 0, fmt.Sprintf("Successfully updated rule '%s'", ruleID), nil
}

// handleFirewallRollback handles firewall rollback command
func (h *FirewallHandler) handleFirewallRollback(ctx context.Context) (int, string, error) {
	log.Info().Msg("Executing firewall rollback")

	h.mu.RLock()
	backup := h.backup
	h.mu.RUnlock()

	if backup == nil || !backup.HasBackup() {
		return 1, "No backup available for rollback", fmt.Errorf("no backup available")
	}

	if err := backup.Rollback(ctx); err != nil {
		return 1, fmt.Sprintf("Failed to rollback firewall: %v", err), err
	}

	return 0, "Firewall rules rolled back successfully", nil
}

// handleFirewallReorderChains handles firewall chain reordering
func (h *FirewallHandler) handleFirewallReorderChains(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	chainNames := args.ChainNames

	log.Info().
		Strs("chains", chainNames).
		Msg("Reordering firewall chains")

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before reorder
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before chain reorder")
	}

	result, err := backend.ReorderChains(ctx, chainNames)
	if err != nil {
		// Attempt rollback on failure
		if h.backup.HasBackup() {
			if rollbackErr := h.backup.Rollback(ctx); rollbackErr != nil {
				log.Error().Err(rollbackErr).Msg("Failed to rollback after reorder failure")
			}
		}
		return 1, fmt.Sprintf("Failed to reorder chains: %v", err), err
	}

	reorderResult := ReorderResult{
		Success:        true,
		ReorderedCount: len(chainNames),
		Message:        fmt.Sprintf("Successfully reordered %d chains", len(chainNames)),
	}

	if deletedRules, ok := result["deleted_rules"].(int); ok {
		reorderResult.DeletedRules = deletedRules
	}

	resultJSON, _ := json.Marshal(reorderResult)
	return 0, string(resultJSON), nil
}

// handleFirewallReorderRules handles firewall rule reordering within a chain
func (h *FirewallHandler) handleFirewallReorderRules(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	chainName := args.ChainName
	rules := args.Rules

	log.Info().
		Str("chain", chainName).
		Int("ruleCount", len(rules)).
		Msg("Reordering firewall rules")

	backend, err := h.getBackend(ctx)
	if err != nil {
		return 1, fmt.Sprintf("Failed to get firewall backend: %v", err), err
	}

	// Create backup before reorder
	if err := h.backup.CreateBackup(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before rule reorder")
	}

	if err := backend.ReorderRules(ctx, chainName, rules); err != nil {
		// Attempt rollback on failure
		if h.backup.HasBackup() {
			if rollbackErr := h.backup.Rollback(ctx); rollbackErr != nil {
				log.Error().Err(rollbackErr).Msg("Failed to rollback after reorder failure")
			}
		}
		return 1, fmt.Sprintf("Failed to reorder rules in chain '%s': %v", chainName, err), err
	}

	reorderResult := ReorderResult{
		Success:        true,
		ReorderedCount: len(rules),
		Message:        fmt.Sprintf("Successfully reordered %d rules in chain '%s'", len(rules), chainName),
	}

	resultJSON, _ := json.Marshal(reorderResult)
	return 0, string(resultJSON), nil
}

// GetDetector returns the firewall detector for external use
func (h *FirewallHandler) GetDetector() *FirewallDetector {
	return h.detector
}

// GetBackend returns the current backend for external use
func (h *FirewallHandler) GetBackend() FirewallBackend {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.backend
}

// GetBackupManager returns the backup manager for external use
func (h *FirewallHandler) GetBackupManager() *BackupManager {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.backup
}

// CollectAllRules collects all firewall rules from the system
// Returns rules in the format compatible with utils.FirewallSyncPayload
func (h *FirewallHandler) CollectAllRules(ctx context.Context) (map[string][]common.FirewallRule, error) {
	backend, err := h.getBackend(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall backend: %w", err)
	}

	// Get all chains by listing rules without filter
	rules, err := backend.ListRules(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list firewall rules: %w", err)
	}

	// Group rules by chain
	chains := make(map[string][]common.FirewallRule)
	for _, rule := range rules {
		chainName := rule.Chain
		if chainName == "" {
			chainName = "INPUT"
		}
		chains[chainName] = append(chains[chainName], rule)
	}

	return chains, nil
}

// IsFirewallAvailable checks if firewall functionality is available
func (h *FirewallHandler) IsFirewallAvailable(ctx context.Context) bool {
	result := h.detector.Detect(ctx)
	return !result.Disabled && result.HighLevel == HighLevelNone
}

// GetHighLevelFirewall returns the detected high-level firewall tool name if any
func (h *FirewallHandler) GetHighLevelFirewall(ctx context.Context) (bool, string) {
	result := h.detector.Detect(ctx)
	if result.HighLevel != HighLevelNone {
		return true, string(result.HighLevel)
	}
	return false, ""
}
