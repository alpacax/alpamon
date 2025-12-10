package firewall

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// IptablesBackend implements FirewallBackend interface for iptables
type IptablesBackend struct {
	executor common.CommandExecutor
}

// NewIptablesBackend creates a new iptables backend
func NewIptablesBackend(executor common.CommandExecutor) *IptablesBackend {
	return &IptablesBackend{
		executor: executor,
	}
}

// Name returns the backend name
func (s *IptablesBackend) Name() string {
	return "iptables"
}

// Detect checks if iptables is available
func (s *IptablesBackend) Detect(ctx context.Context) bool {
	exitCode, _, _ := s.executor.RunWithTimeout(ctx, 5*time.Second, "which", "iptables")
	return exitCode == 0
}

// AddRule adds a single firewall rule
func (s *IptablesBackend) AddRule(ctx context.Context, rule *common.FirewallRule) error {
	args := s.buildAddRuleArgs(rule)
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", args[0], args[1:]...)
	if err != nil {
		return fmt.Errorf("failed to execute iptables: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("iptables add rule failed: %s", output)
	}
	return nil
}

// buildAddRuleArgs builds iptables command arguments for adding a rule
func (s *IptablesBackend) buildAddRuleArgs(rule *common.FirewallRule) []string {
	chainName := rule.Chain
	if chainName == "" {
		chainName = "INPUT"
	}

	args := []string{"iptables", "-A", chainName}

	// Add protocol
	if rule.Protocol != "" && rule.Protocol != "all" {
		args = append(args, "-p", rule.Protocol)
	}

	// Add source CIDR
	if rule.Source != "" && rule.Source != "0.0.0.0/0" {
		args = append(args, "-s", rule.Source)
	}

	// Add destination CIDR
	if rule.Destination != "" && rule.Destination != "0.0.0.0/0" {
		args = append(args, "-d", rule.Destination)
	}

	// Add port matches
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		if len(rule.DPorts) > 0 {
			// Multiple ports using multiport
			ports := make([]string, len(rule.DPorts))
			for i, p := range rule.DPorts {
				ports[i] = strconv.Itoa(p)
			}
			args = append(args, "-m", "multiport", "--dports", strings.Join(ports, ","))
		} else if rule.PortStart > 0 {
			if rule.PortEnd > 0 && rule.PortEnd != rule.PortStart {
				// Port range
				args = append(args, "--dport", fmt.Sprintf("%d:%d", rule.PortStart, rule.PortEnd))
			} else {
				// Single port
				args = append(args, "--dport", strconv.Itoa(rule.PortStart))
			}
		}
	}

	// Add ICMP type
	if rule.Protocol == "icmp" && rule.ICMPType != "" {
		args = append(args, "--icmp-type", rule.ICMPType)
	}

	// Add target
	target := rule.Target
	if target == "" {
		target = "ACCEPT"
	}
	args = append(args, "-j", strings.ToUpper(target))

	// Add comment with rule ID
	if rule.RuleID != "" {
		comment := utils.BuildFirewallComment("", rule.RuleID, rule.RuleType)
		args = append(args, "-m", "comment", "--comment", comment)
	}

	return args
}

// DeleteRule removes a single firewall rule by ID
func (s *IptablesBackend) DeleteRule(ctx context.Context, ruleID, chainName string) error {
	if chainName == "" {
		chainName = "INPUT"
	}

	// Get current rules to find the one to delete
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "iptables", "-L", chainName, "--line-numbers", "-n", "-v")
	if err != nil {
		return fmt.Errorf("failed to list iptables rules: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to list iptables rules: %s", output)
	}

	// Find rule with matching rule ID in comment
	lines := strings.Split(output, "\n")
	lineNum := 0

	for _, line := range lines {
		if strings.Contains(line, ruleID) {
			// Extract line number from the beginning of the line
			parts := strings.Fields(line)
			if len(parts) > 0 {
				if num, err := strconv.Atoi(parts[0]); err == nil {
					lineNum = num
					break
				}
			}
		}
	}

	if lineNum == 0 {
		return fmt.Errorf("rule with ID %s not found in chain %s", ruleID, chainName)
	}

	// Delete by line number
	exitCode, output, err = s.executor.RunAsUser(ctx, "root", "iptables", "-D", chainName, strconv.Itoa(lineNum))
	if err != nil {
		return fmt.Errorf("failed to delete iptables rule: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to delete iptables rule: %s", output)
	}

	log.Debug().Msgf("Deleted iptables rule %s from chain %s (line %d)", ruleID, chainName, lineNum)
	return nil
}

// FlushChain removes all rules from a chain
func (s *IptablesBackend) FlushChain(ctx context.Context, chainName string) error {
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "iptables", "-F", chainName)
	if err != nil {
		return fmt.Errorf("failed to flush iptables chain: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to flush iptables chain %s: %s", chainName, output)
	}
	log.Debug().Msgf("Flushed iptables chain: %s", chainName)
	return nil
}

// DeleteChain deletes a chain entirely
func (s *IptablesBackend) DeleteChain(ctx context.Context, chainName string) error {
	// First flush the chain
	if err := s.FlushChain(ctx, chainName); err != nil {
		return fmt.Errorf("failed to flush chain before delete: %w", err)
	}

	// Then delete the chain
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "iptables", "-X", chainName)
	if err != nil {
		return fmt.Errorf("failed to delete iptables chain: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to delete iptables chain %s: %s", chainName, output)
	}
	log.Debug().Msgf("Deleted iptables chain: %s", chainName)
	return nil
}

// ListRules returns all rules in a chain
func (s *IptablesBackend) ListRules(ctx context.Context, chainName string) ([]common.FirewallRule, error) {
	args := []string{"iptables-save"}
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", args[0], args[1:]...)
	if err != nil {
		return nil, fmt.Errorf("failed to run iptables-save: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("iptables-save failed: %s", output)
	}

	rules := s.parseIptablesSaveOutput(output, chainName)
	return rules, nil
}

// parseIptablesSaveOutput parses iptables-save output to extract rules
func (s *IptablesBackend) parseIptablesSaveOutput(output, filterChain string) []common.FirewallRule {
	var rules []common.FirewallRule
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip non-rule lines
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			continue
		}

		rule := s.parseIptablesSaveRuleLine(line)
		if rule == nil {
			continue
		}

		// Filter by chain if specified
		if filterChain != "" && rule.Chain != filterChain {
			continue
		}

		rules = append(rules, *rule)
	}

	return rules
}

// parseIptablesSaveRuleLine parses a single iptables-save rule line
func (s *IptablesBackend) parseIptablesSaveRuleLine(line string) *common.FirewallRule {
	// Remove -A or -I prefix
	if strings.HasPrefix(line, "-A ") {
		line = strings.TrimPrefix(line, "-A ")
	} else if strings.HasPrefix(line, "-I ") {
		line = strings.TrimPrefix(line, "-I ")
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	rule := &common.FirewallRule{
		Chain:       parts[0],
		Source:      "0.0.0.0/0",
		Destination: "0.0.0.0/0",
		Protocol:    "all",
		Target:      "ACCEPT",
	}

	// Parse arguments
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "-p", "--protocol":
			if i+1 < len(parts) {
				rule.Protocol = parts[i+1]
				i++
			}
		case "-s", "--source":
			if i+1 < len(parts) {
				rule.Source = parts[i+1]
				i++
			}
		case "-d", "--destination":
			if i+1 < len(parts) {
				rule.Destination = parts[i+1]
				i++
			}
		case "-j", "--jump":
			if i+1 < len(parts) {
				rule.Target = strings.ToUpper(parts[i+1])
				i++
			}
		case "--dport":
			if i+1 < len(parts) {
				portStr := parts[i+1]
				if strings.Contains(portStr, ":") {
					// Port range
					portRange := strings.Split(portStr, ":")
					if len(portRange) == 2 {
						if start, err := strconv.Atoi(portRange[0]); err == nil {
							rule.PortStart = start
						}
						if end, err := strconv.Atoi(portRange[1]); err == nil {
							rule.PortEnd = end
						}
					}
				} else {
					// Single port
					if port, err := strconv.Atoi(portStr); err == nil {
						rule.PortStart = port
					}
				}
				i++
			}
		case "--dports":
			if i+1 < len(parts) {
				portStrs := strings.Split(parts[i+1], ",")
				for _, ps := range portStrs {
					if port, err := strconv.Atoi(ps); err == nil {
						rule.DPorts = append(rule.DPorts, port)
					}
				}
				i++
			}
		case "--icmp-type":
			if i+1 < len(parts) {
				rule.ICMPType = parts[i+1]
				i++
			}
		case "--comment":
			if i+1 < len(parts) {
				comment := strings.Trim(parts[i+1], "\"")
				ruleID, ruleType, _ := utils.ParseFirewallComment(comment)
				rule.RuleID = ruleID
				rule.RuleType = ruleType
				i++
			}
		}
	}

	return rule
}

// BatchApply applies multiple rules atomically
func (s *IptablesBackend) BatchApply(ctx context.Context, chainName string, rules []common.FirewallRule) (applied int, failed []string, err error) {
	for i, rule := range rules {
		ruleCopy := rule
		if ruleCopy.Chain == "" {
			ruleCopy.Chain = chainName
		}

		if addErr := s.AddRule(ctx, &ruleCopy); addErr != nil {
			failed = append(failed, fmt.Sprintf("rule[%d]: %v", i, addErr))
			log.Error().Err(addErr).Msgf("Failed to add rule %d", i)
			continue
		}
		applied++
	}

	if len(failed) > 0 {
		err = fmt.Errorf("batch apply partially failed: %d applied, %d failed", applied, len(failed))
	}

	return applied, failed, err
}

// ReorderChains reorders jump rules in INPUT chain
func (s *IptablesBackend) ReorderChains(ctx context.Context, chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting iptables chain reordering")

	// Get current INPUT chain rules
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "iptables", "-L", "INPUT", "--line-numbers", "-n")
	if err != nil {
		return nil, fmt.Errorf("failed to list INPUT chain rules: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list INPUT chain rules: %s", output)
	}

	// Find alpacon jump rule line numbers
	var jumpLines []int
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		for _, chainName := range chainNames {
			if parts[1] == chainName || (len(parts) > 2 && parts[2] == chainName) {
				if lineNum, err := strconv.Atoi(parts[0]); err == nil && lineNum > 0 {
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

	// Sort in reverse order (delete from bottom to preserve line numbers)
	for i := 0; i < len(jumpLines); i++ {
		for j := i + 1; j < len(jumpLines); j++ {
			if jumpLines[i] < jumpLines[j] {
				jumpLines[i], jumpLines[j] = jumpLines[j], jumpLines[i]
			}
		}
	}

	// Delete old jump rules
	for _, lineNum := range jumpLines {
		exitCode, errOutput, _ := s.executor.RunAsUser(ctx, "root", "iptables", "-D", "INPUT", strconv.Itoa(lineNum))
		if exitCode != 0 {
			return nil, fmt.Errorf("failed to delete rule at line %d: %s", lineNum, errOutput)
		}
		log.Debug().Msgf("Deleted rule at line: %d", lineNum)
	}

	// Add jump rules in new order
	for _, chainName := range chainNames {
		exitCode, errOutput, _ := s.executor.RunAsUser(ctx, "root", "iptables", "-A", "INPUT", "-j", chainName)
		if exitCode != 0 {
			return nil, fmt.Errorf("failed to add jump rule for chain %s: %s", chainName, errOutput)
		}
		log.Debug().Msgf("Added jump rule for chain: %s", chainName)
	}

	return map[string]interface{}{
		"reordered_chains": chainNames,
		"deleted_rules":    len(jumpLines),
	}, nil
}

// ReorderRules reorders rules within a chain
func (s *IptablesBackend) ReorderRules(ctx context.Context, chainName string, rules []common.FirewallRule) error {
	// Flush the chain first
	if err := s.FlushChain(ctx, chainName); err != nil {
		return fmt.Errorf("failed to flush chain before reorder: %w", err)
	}

	// Add rules in the new order
	for i, rule := range rules {
		ruleCopy := rule
		ruleCopy.Chain = chainName
		if err := s.AddRule(ctx, &ruleCopy); err != nil {
			return fmt.Errorf("failed to add rule %d during reorder: %w", i, err)
		}
	}

	return nil
}

// Backup creates a backup of current firewall state
func (s *IptablesBackend) Backup(ctx context.Context) (string, error) {
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "iptables-save")
	if err != nil {
		return "", fmt.Errorf("failed to run iptables-save: %w", err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("iptables-save failed: %s", output)
	}
	log.Debug().Msg("Created iptables backup")
	return output, nil
}

// Restore restores firewall state from backup
func (s *IptablesBackend) Restore(ctx context.Context, backup string) error {
	if backup == "" {
		return fmt.Errorf("empty backup provided")
	}

	log.Warn().Msg("Restoring iptables backup")

	// Write backup to temp file
	tmpFile := fmt.Sprintf("/tmp/iptables-backup-%d-%d.rules", os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	if _, err := f.WriteString(backup); err != nil {
		f.Close()
		return fmt.Errorf("failed to write backup: %w", err)
	}
	f.Close()

	// Restore using iptables-restore
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "iptables-restore", tmpFile)
	if err != nil {
		return fmt.Errorf("failed to run iptables-restore: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("iptables-restore failed: %s", output)
	}

	log.Info().Msg("Successfully restored iptables backup")
	return nil
}

// Compile-time check to ensure IptablesBackend implements FirewallBackend
var _ FirewallBackend = (*IptablesBackend)(nil)

// Suppress unused import warning for regexp
var _ = regexp.Compile
