package runner

import (
	"fmt"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// firewallReorderRules handles the firewall-reorder-rules command
// Flushes a chain and reapplies all rules in the specified order
// TODO: Implement zero-downtime reordering to prevent complete firewall shutdown:
//  1. Create temporary table/chain with new rules in desired order
//  2. Atomically swap with existing table/chain
//  3. Clean up old table/chain
//     This prevents firewall from being completely down during flush+reorder
func (cr *CommandRunner) firewallReorderRules() (exitCode int, result string) {
	log.Info().Msg("Firewall reorder rules command received")

	// Validate required fields
	if len(cr.data.Rules) == 0 {
		return 1, "firewall-reorder-rules: rules array is required"
	}

	log.Debug().Msgf("Reordering %d rules", len(cr.data.Rules))

	// No explicit flush needed - batch operation handles chain management
	// Rules already contain complete chain information

	// Use the common batch apply logic with flush (same as batch operation)
	appliedRules, failedRules, rolledBack, rollbackReason := cr.applyRulesBatchWithFlush()

	// Prepare response
	if rolledBack {
		return 1, fmt.Sprintf(`{"success": false, "error": "Failed to reorder rules", "applied_rules": %d, "failed_rules": %d, "rolled_back": true, "rollback_reason": "%s"}`,
			appliedRules, len(failedRules), rollbackReason)
	}

	log.Info().Msgf("Successfully reordered %d rules", appliedRules)
	return 0, fmt.Sprintf(`{"success": true, "message": "Rules reordered successfully", "applied_rules": %d, "failed_rules": [], "rolled_back": false}`,
		appliedRules)
}

// firewallReorderChains handles the firewall-reorder-chains command
// Reorders INPUT chain jump rules for security groups
// TODO: Implement zero-downtime chain reordering to prevent firewall shutdown:
//  1. Create temporary chain with jump rules in new order
//  2. Atomically swap INPUT chain reference to temporary chain
//  3. Clean up old chain
//     This prevents firewall from being completely down during chain reordering
func (cr *CommandRunner) firewallReorderChains() (exitCode int, result string) {
	log.Info().Msg("Firewall reorder chains command received")

	// Get chain_names from data
	chainNames := cr.data.ChainNames
	if len(chainNames) == 0 {
		return 1, "firewall-reorder-chains: No chain_names provided"
	}

	log.Debug().Msgf("Reordering chains: %v", chainNames)

	// Detect firewall backend
	nftablesInstalled, iptablesInstalled, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("firewall-reorder-chains: Failed to check firewall installation: %v", err)
	}

	var deletedRules int

	// Execute reordering based on backend
	if nftablesInstalled {
		resultData, err := utils.ReorderNftablesChains(chainNames)
		if err != nil {
			log.Error().Err(err).Msg("Failed to reorder firewall chains")
			return 1, fmt.Sprintf("firewall-reorder-chains: %v", err)
		}
		if count, ok := resultData["deleted_rules"].(int); ok {
			deletedRules = count
		}
	} else if iptablesInstalled {
		resultData, err := utils.ReorderIptablesChains(chainNames)
		if err != nil {
			log.Error().Err(err).Msg("Failed to reorder firewall chains")
			return 1, fmt.Sprintf("firewall-reorder-chains: %v", err)
		}
		if count, ok := resultData["deleted_rules"].(int); ok {
			deletedRules = count
		}
	} else {
		return 1, "firewall-reorder-chains: No firewall backend available"
	}

	log.Info().Msgf("Successfully reordered %d chains", len(chainNames))
	return 0, fmt.Sprintf(`{"success": true, "message": "Chains reordered successfully", "reordered_chains": %d, "deleted_rules": %d}`, len(chainNames), deletedRules)
}
