package runner

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// firewallReorderRules handles the firewall-reorder-rules command
// Flushes a chain and reapplies all rules in the specified order
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
	nftablesInstalled, iptablesInstalled, err := checkFirewallAvailability()
	if err != nil {
		return 1, fmt.Sprintf("firewall-reorder-rules: Failed to check firewall installation: %v", err)
	}

	// Flush the chain/table before applying new rules
	var flushExitCode int
	var flushOutput string

	if nftablesInstalled {
		// For nftables, chain_name is actually the table name (security group)
		// Flush all chains in the table (uses 'ip' family as defined in executeNftablesRule)
		flushExitCode, flushOutput = runFirewallCommand(
			[]string{"nft", "flush", "table", "ip", cr.data.ChainName},
			10,
		)
	} else if iptablesInstalled {
		// For iptables, chain_name is the actual chain name
		flushExitCode, flushOutput = runFirewallCommand(
			[]string{"iptables", "-F", cr.data.ChainName},
			10,
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
func (cr *CommandRunner) firewallReorderChains() (exitCode int, result string) {
	log.Info().Msg("Firewall reorder chains command received")

	// Get chain_names from data
	chainNames := cr.data.ChainNames
	if len(chainNames) == 0 {
		return 1, "firewall-reorder-chains: No chain_names provided"
	}

	log.Debug().Msgf("Reordering chains: %v", chainNames)

	// Detect firewall backend
	nftablesInstalled, iptablesInstalled, err := checkFirewallAvailability()
	if err != nil {
		return 1, fmt.Sprintf("firewall-reorder-chains: Failed to check firewall installation: %v", err)
	}

	var deletedRules int

	// Execute reordering based on backend
	if nftablesInstalled {
		resultData, err := reorderNftablesChains(chainNames)
		if err != nil {
			log.Error().Err(err).Msg("Failed to reorder firewall chains")
			return 1, fmt.Sprintf("firewall-reorder-chains: %v", err)
		}
		if count, ok := resultData["deleted_rules"].(int); ok {
			deletedRules = count
		}
	} else if iptablesInstalled {
		resultData, err := reorderIptablesChains(chainNames)
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

// reorderNftablesChains reorders nftables INPUT chain jump rules
func reorderNftablesChains(chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting nftables chain reordering")

	// 1. Backup current ruleset
	exitCode, backup := runFirewallCommand([]string{"nft", "list", "ruleset"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to backup nftables ruleset")
	}

	// 2. Get current INPUT chain rules with handles
	exitCode, output := runFirewallCommand([]string{"nft", "-a", "list", "chain", "inet", "filter", "INPUT"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list INPUT chain rules")
	}

	// 3. Parse and find alpacon jump rule handles
	jumpHandles := []string{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// Check if line contains jump to any of our chains
		isJumpRule := false
		for _, chainName := range chainNames {
			if strings.Contains(line, fmt.Sprintf("jump %s", chainName)) {
				isJumpRule = true
				break
			}
		}

		if !isJumpRule {
			continue
		}

		// Extract handle number from line (format: "... # handle 123")
		handleRegex := regexp.MustCompile(`# handle (\d+)`)
		matches := handleRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			jumpHandles = append(jumpHandles, matches[1])
			log.Debug().Msgf("Found jump rule handle: %s", matches[1])
		}
	}

	if len(jumpHandles) == 0 {
		log.Warn().Msg("No jump rules found to reorder")
		return map[string]interface{}{
			"reordered_chains": chainNames,
			"deleted_rules":    0,
		}, nil
	}

	// 4. Delete old jump rules
	for _, handle := range jumpHandles {
		exitCode, errOutput := runFirewallCommand(
			[]string{"nft", "delete", "rule", "inet", "filter", "INPUT", "handle", handle},
			10,
		)
		if exitCode != 0 {
			// Restore backup on error
			log.Error().Msgf("Failed to delete rule handle %s: %s", handle, errOutput)
			restoreNftablesBackup(backup)
			return nil, fmt.Errorf("failed to delete rule handle %s", handle)
		}
		log.Debug().Msgf("Deleted rule handle: %s", handle)
	}

	// 5. Add jump rules in new order
	for _, chainName := range chainNames {
		exitCode, errOutput := runFirewallCommand(
			[]string{"nft", "add", "rule", "inet", "filter", "INPUT", "jump", chainName},
			10,
		)
		if exitCode != 0 {
			// Restore backup on error
			log.Error().Msgf("Failed to add jump rule for chain %s: %s", chainName, errOutput)
			restoreNftablesBackup(backup)
			return nil, fmt.Errorf("failed to add jump rule for chain %s", chainName)
		}
		log.Debug().Msgf("Added jump rule for chain: %s", chainName)
	}

	return map[string]interface{}{
		"reordered_chains": chainNames,
		"deleted_rules":    len(jumpHandles),
	}, nil
}

// reorderIptablesChains reorders iptables INPUT chain jump rules
func reorderIptablesChains(chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting iptables chain reordering")

	// 1. Backup current rules
	exitCode, backup := runFirewallCommand([]string{"iptables-save"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to backup iptables rules")
	}

	// 2. Get current INPUT chain rules
	exitCode, output := runFirewallCommand([]string{"iptables", "-L", "INPUT", "--line-numbers", "-n"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list INPUT chain rules")
	}

	// 3. Find alpacon jump rule line numbers (in reverse order)
	jumpLines := []int{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		// Check if this is a jump rule to one of our chains
		// Format: "1  target  prot  opt  source  destination"
		// Target will be the chain name for jump rules
		for _, chainName := range chainNames {
			if parts[1] == chainName || (len(parts) > 2 && parts[2] == chainName) {
				// Parse line number
				lineNum := 0
				_, err := fmt.Sscanf(parts[0], "%d", &lineNum)
				if err == nil && lineNum > 0 {
					jumpLines = append(jumpLines, lineNum)
					log.Debug().Msgf("Found jump rule at line: %d for chain: %s", lineNum, chainName)
					break
				}
			}
		}
	}

	if len(jumpLines) == 0 {
		log.Warn().Msg("No jump rules found to reorder")
		return map[string]interface{}{
			"reordered_chains": chainNames,
			"deleted_rules":    0,
		}, nil
	}

	// Sort line numbers in reverse order to preserve numbering during deletion
	for i := 0; i < len(jumpLines); i++ {
		for j := i + 1; j < len(jumpLines); j++ {
			if jumpLines[i] < jumpLines[j] {
				jumpLines[i], jumpLines[j] = jumpLines[j], jumpLines[i]
			}
		}
	}

	// 4. Delete old jump rules (in reverse order)
	for _, lineNum := range jumpLines {
		exitCode, errOutput := runFirewallCommand(
			[]string{"iptables", "-D", "INPUT", fmt.Sprintf("%d", lineNum)},
			10,
		)
		if exitCode != 0 {
			// Restore backup on error
			log.Error().Msgf("Failed to delete rule at line %d: %s", lineNum, errOutput)
			restoreIptablesBackup(backup)
			return nil, fmt.Errorf("failed to delete rule at line %d", lineNum)
		}
		log.Debug().Msgf("Deleted rule at line: %d", lineNum)
	}

	// 5. Add jump rules in new order
	for _, chainName := range chainNames {
		exitCode, errOutput := runFirewallCommand(
			[]string{"iptables", "-A", "INPUT", "-j", chainName},
			10,
		)
		if exitCode != 0 {
			// Restore backup on error
			log.Error().Msgf("Failed to add jump rule for chain %s: %s", chainName, errOutput)
			restoreIptablesBackup(backup)
			return nil, fmt.Errorf("failed to add jump rule for chain %s", chainName)
		}
		log.Debug().Msgf("Added jump rule for chain: %s", chainName)
	}

	return map[string]interface{}{
		"reordered_chains": chainNames,
		"deleted_rules":    len(jumpLines),
	}, nil
}

// restoreNftablesBackup restores nftables ruleset from backup
func restoreNftablesBackup(backup string) {
	log.Warn().Msg("Restoring nftables backup")

	// Create temporary file securely with O_EXCL to prevent race conditions
	tmpFile := fmt.Sprintf("/tmp/nft-backup-%d-%d.nft", os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create nftables backup temp file")
		return
	}
	defer os.Remove(tmpFile)

	// Write backup content
	if _, err := f.WriteString(backup); err != nil {
		log.Error().Err(err).Msg("Failed to write nftables backup")
		f.Close()
		return
	}
	f.Close()

	// First flush current rules
	runFirewallCommand([]string{"nft", "flush", "ruleset"}, 10)

	// Then restore from backup file
	exitCode, output := runFirewallCommand([]string{"nft", "-f", tmpFile}, 10)

	if exitCode != 0 {
		log.Error().Msgf("Failed to restore nftables backup: %s", output)
	} else {
		log.Info().Msg("Successfully restored nftables backup")
	}
}

// restoreIptablesBackup restores iptables rules from backup
func restoreIptablesBackup(backup string) {
	log.Warn().Msg("Restoring iptables backup")

	// Create temporary file securely with O_EXCL to prevent race conditions
	tmpFile := fmt.Sprintf("/tmp/iptables-backup-%d-%d.rules", os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create iptables backup temp file")
		return
	}
	defer os.Remove(tmpFile)

	// Write backup content
	if _, err := f.WriteString(backup); err != nil {
		log.Error().Err(err).Msg("Failed to write iptables backup")
		f.Close()
		return
	}
	f.Close()

	// Restore from backup file
	exitCode, output := runFirewallCommand([]string{"iptables-restore", tmpFile}, 10)

	if exitCode != 0 {
		log.Error().Msgf("Failed to restore iptables backup: %s", output)
	} else {
		log.Info().Msg("Successfully restored iptables backup")
	}
}
