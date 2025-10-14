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

// normalizeChainType converts chain type to uppercase
func normalizeChainType(chain string) string {
	return strings.ToUpper(chain)
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
