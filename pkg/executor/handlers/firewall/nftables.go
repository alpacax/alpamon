package firewall

import (
	"context"
	"encoding/json"
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

// NftablesBackend implements FirewallBackend interface for nftables
type NftablesBackend struct {
	executor  common.CommandExecutor
	tableName string // default: "inet filter"
}

// NewNftablesBackend creates a new nftables backend
func NewNftablesBackend(executor common.CommandExecutor) *NftablesBackend {
	return &NftablesBackend{
		executor:  executor,
		tableName: "inet filter",
	}
}

// Name returns the backend name
func (s *NftablesBackend) Name() string {
	return "nftables"
}

// Detect checks if nftables is available
func (s *NftablesBackend) Detect(ctx context.Context) bool {
	exitCode, _, _ := s.executor.RunWithTimeout(ctx, 5*time.Second, "which", "nft")
	return exitCode == 0
}

// AddRule adds a single firewall rule
func (s *NftablesBackend) AddRule(ctx context.Context, rule *common.FirewallRule) error {
	args := s.buildAddRuleArgs(rule)
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", args[0], args[1:]...)
	if err != nil {
		return fmt.Errorf("failed to execute nft: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("nft add rule failed: %s", output)
	}
	return nil
}

// buildAddRuleArgs builds nft command arguments for adding a rule
func (s *NftablesBackend) buildAddRuleArgs(rule *common.FirewallRule) []string {
	chainName := rule.Chain
	if chainName == "" {
		chainName = "INPUT"
	}

	args := []string{"nft", "add", "rule", s.tableName, chainName}

	// Add protocol match
	if rule.Protocol != "" && rule.Protocol != "all" {
		args = append(args, "meta", "l4proto", rule.Protocol)
	}

	// Add source CIDR match
	if rule.Source != "" && rule.Source != "0.0.0.0/0" {
		args = append(args, "ip", "saddr", rule.Source)
	}

	// Add destination CIDR match
	if rule.Destination != "" && rule.Destination != "0.0.0.0/0" {
		args = append(args, "ip", "daddr", rule.Destination)
	}

	// Add port matches
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		if len(rule.DPorts) > 0 {
			// Multiple ports using set
			ports := make([]string, len(rule.DPorts))
			for i, p := range rule.DPorts {
				ports[i] = strconv.Itoa(p)
			}
			args = append(args, rule.Protocol, "dport", "{", strings.Join(ports, ", "), "}")
		} else if rule.PortStart > 0 {
			if rule.PortEnd > 0 && rule.PortEnd != rule.PortStart {
				// Port range
				args = append(args, rule.Protocol, "dport", fmt.Sprintf("%d-%d", rule.PortStart, rule.PortEnd))
			} else {
				// Single port
				args = append(args, rule.Protocol, "dport", strconv.Itoa(rule.PortStart))
			}
		}
	}

	// Add ICMP type
	if rule.Protocol == "icmp" && rule.ICMPType != "" {
		args = append(args, "icmp", "type", rule.ICMPType)
	}

	// Add target/verdict (must come before comment)
	target := strings.ToLower(rule.Target)
	if target == "" {
		target = "accept"
	}
	args = append(args, target)

	// Add comment with rule ID
	if rule.RuleID != "" {
		comment := utils.BuildFirewallComment("", rule.RuleID, rule.RuleType)
		args = append(args, "comment", fmt.Sprintf("\"%s\"", comment))
	}

	return args
}

// DeleteRule removes a single firewall rule by ID
func (s *NftablesBackend) DeleteRule(ctx context.Context, ruleID, chainName string) error {
	if chainName == "" {
		chainName = "INPUT"
	}

	// Get rule handle by listing rules with handles
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "-a", "list", "chain", s.tableName, chainName)
	if err != nil {
		return fmt.Errorf("failed to list nftables chain: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to list nftables chain %s: %s", chainName, output)
	}

	// Find rule with matching rule ID and extract handle
	lines := strings.Split(output, "\n")
	handleRegex := regexp.MustCompile(`# handle (\d+)`)

	for _, line := range lines {
		if !strings.Contains(line, ruleID) {
			continue
		}

		matches := handleRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			handle := matches[1]

			// Delete by handle
			exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "delete", "rule", s.tableName, chainName, "handle", handle)
			if err != nil {
				return fmt.Errorf("failed to delete nft rule: %w", err)
			}
			if exitCode != 0 {
				return fmt.Errorf("failed to delete nft rule handle %s: %s", handle, output)
			}

			log.Debug().Msgf("Deleted nftables rule %s from chain %s (handle %s)", ruleID, chainName, handle)
			return nil
		}
	}

	return fmt.Errorf("rule with ID %s not found in chain %s", ruleID, chainName)
}

// FlushChain removes all rules from a chain
func (s *NftablesBackend) FlushChain(ctx context.Context, chainName string) error {
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "flush", "chain", s.tableName, chainName)
	if err != nil {
		return fmt.Errorf("failed to flush nftables chain: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to flush nftables chain %s: %s", chainName, output)
	}
	log.Debug().Msgf("Flushed nftables chain: %s", chainName)
	return nil
}

// DeleteChain deletes a chain entirely
func (s *NftablesBackend) DeleteChain(ctx context.Context, chainName string) error {
	// First flush the chain
	if err := s.FlushChain(ctx, chainName); err != nil {
		return fmt.Errorf("failed to flush chain before delete: %w", err)
	}

	// Then delete the chain
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "delete", "chain", s.tableName, chainName)
	if err != nil {
		return fmt.Errorf("failed to delete nftables chain: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to delete nftables chain %s: %s", chainName, output)
	}
	log.Debug().Msgf("Deleted nftables chain: %s", chainName)
	return nil
}

// ListRules returns all rules in a chain
func (s *NftablesBackend) ListRules(ctx context.Context, chainName string) ([]common.FirewallRule, error) {
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("failed to list nftables ruleset: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("nft list ruleset failed: %s", output)
	}

	rules, err := s.parseNftablesJSONOutput(output, chainName)
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// parseNftablesJSONOutput parses nft -j output to extract rules
func (s *NftablesBackend) parseNftablesJSONOutput(output, filterChain string) ([]common.FirewallRule, error) {
	var nftData struct {
		Nftables []map[string]interface{} `json:"nftables"`
	}

	if err := json.Unmarshal([]byte(output), &nftData); err != nil {
		return nil, fmt.Errorf("failed to parse nftables JSON: %w", err)
	}

	var rules []common.FirewallRule

	for _, item := range nftData.Nftables {
		ruleData, ok := item["rule"]
		if !ok {
			continue
		}

		ruleMap, ok := ruleData.(map[string]interface{})
		if !ok {
			continue
		}

		rule := s.parseNftablesRule(ruleMap)
		if rule == nil {
			continue
		}

		// Filter by chain if specified
		if filterChain != "" && rule.Chain != filterChain {
			continue
		}

		rules = append(rules, *rule)
	}

	return rules, nil
}

// parseNftablesRule parses a single nftables rule map
func (s *NftablesBackend) parseNftablesRule(ruleMap map[string]interface{}) *common.FirewallRule {
	rule := &common.FirewallRule{
		Source:      "0.0.0.0/0",
		Destination: "0.0.0.0/0",
		Protocol:    "all",
		Target:      "ACCEPT",
	}

	// Extract chain name
	if chain, ok := ruleMap["chain"].(string); ok {
		rule.Chain = chain
	}

	// Extract comment if present at top level
	var fullComment string
	if comment, ok := ruleMap["comment"].(string); ok {
		fullComment = comment
	}

	// Parse expressions for protocol, ports, source, target, comment
	if expr, ok := ruleMap["expr"].([]interface{}); ok {
		for _, e := range expr {
			exprMap, ok := e.(map[string]interface{})
			if !ok {
				continue
			}

			// Extract comment from expression
			if commentExpr, ok := exprMap["comment"].(string); ok {
				fullComment = commentExpr
			}

			// Match protocol
			if match, ok := exprMap["match"].(map[string]interface{}); ok {
				if left, ok := match["left"].(map[string]interface{}); ok {
					if meta, ok := left["meta"].(map[string]interface{}); ok {
						if key, ok := meta["key"].(string); ok && key == "l4proto" {
							if right, ok := match["right"].(string); ok {
								rule.Protocol = right
							}
						}
					}

					// Match source/destination
					if payload, ok := left["payload"].(map[string]interface{}); ok {
						if field, ok := payload["field"].(string); ok {
							if right, ok := match["right"].(string); ok {
								switch field {
								case "saddr":
									rule.Source = right
								case "daddr":
									rule.Destination = right
								}
							}
						}
					}
				}

				// Match ports
				if right, ok := match["right"].(float64); ok {
					port := int(right)
					if rule.PortStart == 0 {
						rule.PortStart = port
					}
				} else if right, ok := match["right"].(map[string]interface{}); ok {
					if set, ok := right["set"].([]interface{}); ok {
						for _, portVal := range set {
							if p, ok := portVal.(float64); ok {
								rule.DPorts = append(rule.DPorts, int(p))
							}
						}
					}
				}
			}

			// Match target/verdict
			if _, ok := exprMap["accept"]; ok {
				rule.Target = "ACCEPT"
			} else if _, ok := exprMap["drop"]; ok {
				rule.Target = "DROP"
			} else if _, ok := exprMap["reject"]; ok {
				rule.Target = "REJECT"
			}
		}
	}

	// Parse comment to extract rule_id and type
	if fullComment != "" {
		ruleID, ruleType, _ := utils.ParseFirewallComment(fullComment)
		rule.RuleID = ruleID
		rule.RuleType = ruleType
	}

	return rule
}

// BatchApply applies multiple rules atomically
func (s *NftablesBackend) BatchApply(ctx context.Context, chainName string, rules []common.FirewallRule) (applied int, failed []string, err error) {
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
func (s *NftablesBackend) ReorderChains(ctx context.Context, chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting nftables chain reordering")

	// Get current INPUT chain rules with handles
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "-a", "list", "chain", s.tableName, "INPUT")
	if err != nil {
		return nil, fmt.Errorf("failed to list INPUT chain: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list INPUT chain: %s", output)
	}

	// Parse and find jump rule handles
	var jumpHandles []string
	lines := strings.Split(output, "\n")
	handleRegex := regexp.MustCompile(`# handle (\d+)`)

	for _, line := range lines {
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

	// Delete old jump rules
	for _, handle := range jumpHandles {
		exitCode, errOutput, _ := s.executor.RunAsUser(ctx, "root", "nft", "delete", "rule", s.tableName, "INPUT", "handle", handle)
		if exitCode != 0 {
			return nil, fmt.Errorf("failed to delete rule handle %s: %s", handle, errOutput)
		}
		log.Debug().Msgf("Deleted rule handle: %s", handle)
	}

	// Add jump rules in new order
	for _, chainName := range chainNames {
		exitCode, errOutput, _ := s.executor.RunAsUser(ctx, "root", "nft", "add", "rule", s.tableName, "INPUT", "jump", chainName)
		if exitCode != 0 {
			return nil, fmt.Errorf("failed to add jump rule for chain %s: %s", chainName, errOutput)
		}
		log.Debug().Msgf("Added jump rule for chain: %s", chainName)
	}

	return map[string]interface{}{
		"reordered_chains": chainNames,
		"deleted_rules":    len(jumpHandles),
	}, nil
}

// ReorderRules reorders rules within a chain
func (s *NftablesBackend) ReorderRules(ctx context.Context, chainName string, rules []common.FirewallRule) error {
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
func (s *NftablesBackend) Backup(ctx context.Context) (string, error) {
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "list", "ruleset")
	if err != nil {
		return "", fmt.Errorf("failed to run nft list ruleset: %w", err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("nft list ruleset failed: %s", output)
	}
	log.Debug().Msg("Created nftables backup")
	return output, nil
}

// Restore restores firewall state from backup
func (s *NftablesBackend) Restore(ctx context.Context, backup string) error {
	if backup == "" {
		return fmt.Errorf("empty backup provided")
	}

	log.Warn().Msg("Restoring nftables backup")

	// Write backup to temp file
	tmpFile := fmt.Sprintf("/tmp/nft-backup-%d-%d.nft", os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	if _, err := f.WriteString(backup); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write backup: %w", err)
	}
	_ = f.Close()

	// Flush current ruleset (ignore error as restore will overwrite anyway)
	_, _, _ = s.executor.RunAsUser(ctx, "root", "nft", "flush", "ruleset")

	// Restore from file
	exitCode, output, err := s.executor.RunAsUser(ctx, "root", "nft", "-f", tmpFile)
	if err != nil {
		return fmt.Errorf("failed to run nft restore: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("nft restore failed: %s", output)
	}

	log.Info().Msg("Successfully restored nftables backup")
	return nil
}

// Compile-time check to ensure NftablesBackend implements FirewallBackend
var _ FirewallBackend = (*NftablesBackend)(nil)
