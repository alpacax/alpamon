package runner

import (
	"fmt"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// firewallReorderRules handles the firewall-reorder-rules command
// Flushes a chain and reapplies all rules in the specified order
// TODO: Implement zero-downtime reordering to prevent complete firewall shutdown:
//   1. Create temporary table/chain with new rules in desired order
//   2. Atomically swap with existing table/chain
//   3. Clean up old table/chain
//   This prevents firewall from being completely down during flush+reorder
func (cr *CommandRunner) firewallReorderRules() (exitCode int, result string) {
	log.Info().Msgf("Firewall reorder rules command received for chain: %s", cr.data.ChainName)

	// Validate required fields
	if cr.data.ChainName == "" {
		return 1, "firewall-reorder-rules: chain_name is required"
	}
	if len(cr.data.Rules) == 0 {
		return 1, "firewall-reorder-rules: rules array is required"
	}

	log.Debug().Msgf("Reordering %d rules in chain %s", len(cr.data.Rules), cr.data.ChainName)

	// Detect firewall backend
	nftablesInstalled, iptablesInstalled, err := utils.InstallFirewall()
	if err != nil {
		return 1, fmt.Sprintf("firewall-reorder-rules: Failed to check firewall installation: %v", err)
	}

	// Flush the chain/table before applying new rules
	var flushExitCode int
	var flushOutput string

	if nftablesInstalled {
		// For nftables, chain_name is actually the table name (security group)
		flushExitCode, flushOutput = runCmdWithOutput(
			[]string{"nft", "flush", "table", "ip", cr.data.ChainName},
			"root", "", nil, 10,
		)
	} else if iptablesInstalled {
		// For iptables, chain_name is the actual chain name
		flushExitCode, flushOutput = runCmdWithOutput(
			[]string{"iptables", "-F", cr.data.ChainName},
			"root", "", nil, 10,
		)
	} else {
		return 1, "firewall-reorder-rules: No firewall backend available"
	}

	if flushExitCode != 0 {
		log.Error().Msgf("Failed to flush %s: %s", cr.data.ChainName, flushOutput)
		return 1, fmt.Sprintf("firewall-reorder-rules: Failed to flush %s: %s", cr.data.ChainName, flushOutput)
	}

	log.Info().Msgf("Successfully flushed %s", cr.data.ChainName)

	// Use the common batch apply logic with flush (same as batch operation)
	appliedRules, failedRules, rolledBack, rollbackReason := cr.applyRulesBatchWithFlush()

	// Prepare response
	if rolledBack {
		return 1, fmt.Sprintf(`{"success": false, "error": "Failed to reorder rules", "applied_rules": %d, "failed_rules": %d, "rolled_back": true, "rollback_reason": "%s"}`,
			appliedRules, len(failedRules), rollbackReason)
	}

	log.Info().Msgf("Successfully reordered %d rules in chain %s", appliedRules, cr.data.ChainName)
	return 0, fmt.Sprintf(`{"success": true, "message": "Rules reordered successfully", "chain": "%s", "applied_rules": %d, "failed_rules": [], "rolled_back": false}`,
		cr.data.ChainName, appliedRules)
}

// firewallReorderChains handles the firewall-reorder-chains command
// Reorders INPUT chain jump rules for security groups
// TODO: Implement zero-downtime chain reordering to prevent firewall shutdown:
//   1. Create temporary chain with jump rules in new order
//   2. Atomically swap INPUT chain reference to temporary chain
//   3. Clean up old chain
//   This prevents firewall from being completely down during chain reordering
func (cr *CommandRunner) firewallReorderChains() (exitCode int, result string) {
	log.Info().Msg("Firewall reorder chains command received")

	// Get chain_names from data
	chainNames := cr.data.ChainNames
	if len(chainNames) == 0 {
		return 1, "firewall-reorder-chains: No chain_names provided"
	}

	log.Debug().Msgf("Reordering chains: %v", chainNames)

	// Detect firewall backend
	nftablesInstalled, iptablesInstalled, err := utils.InstallFirewall()
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
