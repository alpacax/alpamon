package utils

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Default values matching alpacon-server FirewallRuleSyncSerializer
const (
	DefaultCIDR     = "0.0.0.0/0" // matches serializer default for source/destination
	DefaultPriority = 100         // matches serializer default
	DefaultProtocol = "all"
	DefaultTarget   = "ACCEPT"

	// Rule types for progressive removal
	RuleTypeUnknown = ""        // Rules without type (remove first)
	RuleTypeServer  = "server"  // Server-synced rules (remove second)
	RuleTypeAlpacon = "alpacon" // Alpacon-created rules (remove last)
)

// Temporary flag to disable all firewall functionality
// Set to true to completely disable alpacon firewall management
var FirewallFunctionalityDisabled = true

// FirewallChainSync represents a firewall chain for sync payload
type FirewallChainSync struct {
	Name  string             `json:"name"`
	Rules []FirewallRuleSync `json:"rules"`
}

// FirewallRuleSync represents a single firewall rule for sync
// This matches the alpacon-server FirewallRuleSyncSerializer format
type FirewallRuleSync struct {
	Chain           string `json:"chain"`
	Protocol        string `json:"protocol"`
	PortStart       *int   `json:"port_start,omitempty"`
	PortEnd         *int   `json:"port_end,omitempty"`
	SourceCIDR      string `json:"source_cidr"`
	DestinationCIDR string `json:"destination_cidr,omitempty"`
	Target          string `json:"target"`
	Priority        int    `json:"priority"`
	Dports          string `json:"dports,omitempty"`
	ICMPType        *int   `json:"icmp_type,omitempty"`
	RuleID          string `json:"rule_id,omitempty"`
	RuleType        string `json:"rule_type,omitempty"`
}

// FirewallSyncPayload represents the complete firewall sync payload
type FirewallSyncPayload struct {
	Chains []FirewallChainSync `json:"chains"`
}

// IsFirewallDisabled checks if firewall functionality is disabled
func IsFirewallDisabled() bool {
	return FirewallFunctionalityDisabled
}

// ParseFirewallComment parses firewall rule comment to extract rule_id and type
// Format: "rule_id:{uuid},type:{user|server}" or "existing comment,rule_id:{uuid},type:{user|server}"
// Returns: ruleID, ruleType, existingComment
func ParseFirewallComment(comment string) (ruleID, ruleType, existingComment string) {
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

// BuildFirewallComment builds firewall rule comment with rule_id and type
// Preserves existing comment if present
// Format: "existing comment,rule_id:{uuid},type:{user|server}" or "rule_id:{uuid},type:{user|server}"
func BuildFirewallComment(existingComment, ruleID, ruleType string) string {
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

// GenerateServerRuleID generates a new UUID for server-type firewall rules
func GenerateServerRuleID() string {
	return uuid.New().String()
}

// ParseCommentOrGenerate parses firewall comment and returns rule_id and type
// If not found in comment, generates new UUID and assigns "server" type
func ParseCommentOrGenerate(comment string) (ruleID, ruleType string) {
	if comment != "" {
		parsedID, parsedType, _ := ParseFirewallComment(comment)
		if parsedID != "" {
			ruleID = parsedID
		} else {
			ruleID = GenerateServerRuleID()
		}
		if parsedType != "" {
			ruleType = parsedType
		} else {
			ruleType = "server"
		}
	} else {
		ruleID = GenerateServerRuleID()
		ruleType = "server"
	}
	return ruleID, ruleType
}

// BuildSyncPayload creates sync payload from parsed rules
func BuildSyncPayload(chains map[string][]FirewallRuleSync) *FirewallSyncPayload {
	chainsList := make([]FirewallChainSync, 0)

	for name, rules := range chains {
		if len(rules) > 0 {
			chainsList = append(chainsList, FirewallChainSync{
				Name:  name,
				Rules: rules,
			})
		}
	}

	return &FirewallSyncPayload{
		Chains: chainsList,
	}
}
