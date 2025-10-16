package runner

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// checkFirewallAvailability checks which firewall tool is available
// Reuses installFirewall() from command.go
func checkFirewallAvailability() (nftablesInstalled bool, iptablesInstalled bool, err error) {
	return installFirewall()
}

// runFirewallCommand executes a firewall command using runCmdWithOutput from command.go
func runFirewallCommand(args []string, timeout int) (exitCode int, output string) {
	return runCmdWithOutput(args, "root", "", nil, timeout)
}

// parseFirewallComment parses firewall rule comment to extract rule_id and type
// Format: "rule_id:{uuid},type:{user|server}" or "existing comment,rule_id:{uuid},type:{user|server}"
// Returns: ruleID, ruleType, existingComment
func parseFirewallComment(comment string) (ruleID, ruleType, existingComment string) {
	if comment == "" {
		return "", "", ""
	}

	parts := strings.Split(comment, ",")
	var otherParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "rule_id:") {
			ruleID = strings.TrimPrefix(part, "rule_id:")
		} else if strings.HasPrefix(part, "type:") {
			ruleType = strings.TrimPrefix(part, "type:")
		} else if part != "" {
			otherParts = append(otherParts, part)
		}
	}

	existingComment = strings.Join(otherParts, ",")
	return ruleID, ruleType, existingComment
}

// buildFirewallComment builds firewall rule comment with rule_id and type
// Preserves existing comment if present
// Format: "existing comment,rule_id:{uuid},type:{user|server}" or "rule_id:{uuid},type:{user|server}"
func buildFirewallComment(existingComment, ruleID, ruleType string) string {
	var parts []string

	// Add existing comment first if present
	if existingComment != "" {
		parts = append(parts, existingComment)
	}

	// Add rule_id
	if ruleID != "" {
		parts = append(parts, fmt.Sprintf("rule_id:%s", ruleID))
	}

	// Add type
	if ruleType != "" {
		parts = append(parts, fmt.Sprintf("type:%s", ruleType))
	}

	return strings.Join(parts, ",")
}

// generateServerRuleID generates a new UUID for server-type firewall rules
func generateServerRuleID() string {
	return uuid.New().String()
}

// parseCommentOrGenerate parses firewall comment and returns rule_id and type
// If not found in comment, generates new UUID and assigns "server" type
func parseCommentOrGenerate(comment string) (ruleID, ruleType string) {
	if comment != "" {
		parsedID, parsedType, _ := parseFirewallComment(comment)
		if parsedID != "" {
			ruleID = parsedID
		} else {
			ruleID = generateServerRuleID()
		}
		if parsedType != "" {
			ruleType = parsedType
		} else {
			ruleType = "server"
		}
	} else {
		ruleID = generateServerRuleID()
		ruleType = "server"
	}
	return ruleID, ruleType
}

// recreateNftablesRuleWithComment re-creates an nftables rule with updated comment
// Returns true if re-creation was successful
func recreateNftablesRuleWithComment(tableName string, rule *FirewallRuleSync, newComment string) bool {
	// Build nft add rule command with new comment
	args := []string{"nft", "add", "rule", tableName, rule.Chain}

	// Add protocol match
	if rule.Protocol != "" && rule.Protocol != DefaultProtocol {
		args = append(args, "meta", "l4proto", rule.Protocol)
	}

	// Add source CIDR match
	if rule.SourceCIDR != "" && rule.SourceCIDR != DefaultCIDR {
		args = append(args, "ip", "saddr", rule.SourceCIDR)
	}

	// Add destination CIDR match
	if rule.DestinationCIDR != "" && rule.DestinationCIDR != DefaultCIDR {
		args = append(args, "ip", "daddr", rule.DestinationCIDR)
	}

	// Add port matches
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		if rule.Dports != "" {
			// Multiple ports
			ports := strings.Split(rule.Dports, ",")
			args = append(args, rule.Protocol, "dport", "{")
			args = append(args, ports...)
			args = append(args, "}")
		} else if rule.PortStart != nil {
			if rule.PortEnd != nil && *rule.PortEnd != *rule.PortStart {
				// Port range
				args = append(args, rule.Protocol, "dport", fmt.Sprintf("%d-%d", *rule.PortStart, *rule.PortEnd))
			} else {
				// Single port
				args = append(args, rule.Protocol, "dport", fmt.Sprintf("%d", *rule.PortStart))
			}
		}
	}

	// Add ICMP type match
	if rule.Protocol == "icmp" && rule.ICMPType != nil {
		args = append(args, "icmp", "type", fmt.Sprintf("%d", *rule.ICMPType))
	}

	// Add target/verdict (must come before comment)
	args = append(args, strings.ToLower(rule.Target))

	// Add comment with updated metadata (must come after verdict)
	if newComment != "" {
		args = append(args, "comment", fmt.Sprintf("\"%s\"", newComment))
	}

	// Execute the command
	exitCode, _ := runFirewallCommand(args, 10)
	return exitCode == 0
}

// recreateIptablesRuleWithComment re-creates an iptables rule with updated comment
// Returns true if re-creation was successful
func recreateIptablesRuleWithComment(chainName string, rule *FirewallRuleSync, newComment string) bool {
	// Build iptables insert command (insert at beginning to maintain priority)
	args := []string{"iptables", "-I", chainName}

	// Protocol
	if rule.Protocol != "" && rule.Protocol != DefaultProtocol {
		args = append(args, "-p", rule.Protocol)
	}

	// Source CIDR
	if rule.SourceCIDR != "" && rule.SourceCIDR != DefaultCIDR {
		args = append(args, "-s", rule.SourceCIDR)
	}

	// Destination CIDR
	if rule.DestinationCIDR != "" && rule.DestinationCIDR != DefaultCIDR {
		args = append(args, "-d", rule.DestinationCIDR)
	}

	// Handle ports
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		if rule.Dports != "" {
			args = append(args, "-m", "multiport", "--dports", rule.Dports)
		} else if rule.PortStart != nil {
			if rule.PortEnd != nil && *rule.PortEnd != *rule.PortStart {
				args = append(args, "--dport", fmt.Sprintf("%d:%d", *rule.PortStart, *rule.PortEnd))
			} else {
				args = append(args, "--dport", fmt.Sprintf("%d", *rule.PortStart))
			}
		}
	}

	// ICMP type
	if rule.Protocol == "icmp" && rule.ICMPType != nil {
		args = append(args, "--icmp-type", fmt.Sprintf("%d", *rule.ICMPType))
	}

	// Target
	if rule.Target != "" {
		args = append(args, "-j", rule.Target)
	}

	// Comment with updated metadata
	if newComment != "" {
		args = append(args, "-m", "comment", "--comment", newComment)
	}

	// Execute the command
	exitCode, _ := runFirewallCommand(args, 10)
	return exitCode == 0
}
