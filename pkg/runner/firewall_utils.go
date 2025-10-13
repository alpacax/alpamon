package runner

import (
	"fmt"
	"strconv"
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

// parsePortsFromDPorts converts DPorts array to comma-separated string for server
func parsePortsFromDPorts(dports []int) string {
	if len(dports) == 0 {
		return ""
	}

	var portStrs []string
	for _, port := range dports {
		portStrs = append(portStrs, fmt.Sprintf("%d", port))
	}
	return strings.Join(portStrs, ",")
}

// extractChainNameFromFullName extracts base chain name from full chain name
// e.g., "sg-web_input" -> "sg-web"
func extractChainNameFromFullName(fullName string) string {
	// Remove chain type suffix (_input, _output, _forward)
	parts := strings.Split(fullName, "_")
	if len(parts) > 1 {
		// Check if last part is a chain type
		lastPart := strings.ToLower(parts[len(parts)-1])
		if lastPart == "input" || lastPart == "output" || lastPart == "forward" {
			return strings.Join(parts[:len(parts)-1], "_")
		}
	}
	return fullName
}

// normalizeChainType converts chain type to uppercase
func normalizeChainType(chain string) string {
	return strings.ToUpper(chain)
}

// isBuiltinChain checks if a chain is a built-in chain
func isBuiltinChain(chainName string) bool {
	normalized := strings.ToUpper(chainName)
	return normalized == "INPUT" || normalized == "OUTPUT" || normalized == "FORWARD" ||
		normalized == "PREROUTING" || normalized == "POSTROUTING"
}

// isCustomChain checks if a chain is a custom alpacon chain
func isCustomChain(chainName string) bool {
	// Custom chains typically have underscore or are not built-in
	return !isBuiltinChain(chainName) && chainName != ""
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

// validateFirewallRuleInput validates firewall rule input to prevent command injection
func validateFirewallRuleInput(rule FirewallRuleSync) error {
	// Protocol validation
	validProtocols := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "all": true,
	}
	if !validProtocols[rule.Protocol] {
		return fmt.Errorf("invalid protocol: %s", rule.Protocol)
	}

	// Target validation
	validTargets := map[string]bool{
		"ACCEPT": true, "DROP": true, "REJECT": true, "LOG": true, "RETURN": true,
	}
	if !validTargets[rule.Target] {
		return fmt.Errorf("invalid target: %s", rule.Target)
	}

	// Port validation
	if rule.PortStart != nil {
		if *rule.PortStart < 1 || *rule.PortStart > 65535 {
			return fmt.Errorf("invalid port_start: %d", *rule.PortStart)
		}
	}
	if rule.PortEnd != nil {
		if *rule.PortEnd < 1 || *rule.PortEnd > 65535 {
			return fmt.Errorf("invalid port_end: %d", *rule.PortEnd)
		}
	}
	if rule.PortStart != nil && rule.PortEnd != nil && *rule.PortStart > *rule.PortEnd {
		return fmt.Errorf("port_start (%d) cannot be greater than port_end (%d)", *rule.PortStart, *rule.PortEnd)
	}

	// ICMP type validation
	if rule.ICMPType != nil {
		if *rule.ICMPType < 0 || *rule.ICMPType > 255 {
			return fmt.Errorf("invalid icmp_type: %d", *rule.ICMPType)
		}
	}

	// CIDR validation (basic)
	if rule.SourceCIDR != "" {
		if !isValidCIDR(rule.SourceCIDR) {
			return fmt.Errorf("invalid source_cidr: %s", rule.SourceCIDR)
		}
	}
	if rule.DestinationCIDR != "" {
		if !isValidCIDR(rule.DestinationCIDR) {
			return fmt.Errorf("invalid destination_cidr: %s", rule.DestinationCIDR)
		}
	}

	// Chain name validation (prevent injection)
	if !isValidChainName(rule.Chain) {
		return fmt.Errorf("invalid chain name: %s", rule.Chain)
	}

	return nil
}

// isValidCIDR performs basic CIDR validation
func isValidCIDR(cidr string) bool {
	// Basic format check: IP/mask
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return false
	}

	// Check IP part (simplified)
	ip := parts[0]
	if ip == "0.0.0.0" || ip == "anywhere" {
		return true
	}

	// Check mask part
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return false
	}

	return true
}

// isValidChainName validates chain name to prevent command injection
// Allows alphanumeric, underscore, hyphen, and dot (for alpacon- prefix)
func isValidChainName(chainName string) bool {
	if chainName == "" {
		return false
	}

	// Allow alphanumeric, underscore, hyphen, and dot
	// This allows both "default" and "alpacon-mygroup" formats
	for _, char := range chainName {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return false
		}
	}

	return true
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
