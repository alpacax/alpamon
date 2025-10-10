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

// generateServerRuleID generates a new UUID for server-type firewall rules
func generateServerRuleID() string {
	return uuid.New().String()
}
