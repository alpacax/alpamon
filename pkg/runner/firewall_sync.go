package runner

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Default values matching alpacon-server FirewallRuleSyncSerializer
const (
	DefaultCIDR     = "0.0.0.0/0" // matches serializer default for source/destination
	DefaultPriority = 100         // matches serializer default
	DefaultProtocol = "all"
	DefaultTarget   = "ACCEPT"

	// Firewall sync API endpoint
	FirewallSyncURL = "/api/firewall/agent/sync/"

	// Rule types for progressive removal
	RuleTypeUnknown = ""         // Rules without type (remove first)
	RuleTypeServer  = "server"   // Server-synced rules (remove second)
	RuleTypeAlpacon = "alpacon"  // Alpacon-created rules (remove last)
)

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

// Cached firewall rules information
var firewallRulesCache struct {
	rules      map[string][]FirewallRuleSync
	lastUpdate time.Time
	mu         sync.RWMutex
}

// Cache validity duration (5 minutes)
const cacheValidityDuration = 5 * time.Minute

// collectFirewallRules collects current firewall rules from the system
// This is the reverse operation of command.go firewall application logic
func collectFirewallRules() (*FirewallSyncPayload, error) {
	// Check cache first
	firewallRulesCache.mu.RLock()
	if time.Since(firewallRulesCache.lastUpdate) < cacheValidityDuration &&
		len(firewallRulesCache.rules) > 0 {
		cachedRules := firewallRulesCache.rules
		firewallRulesCache.mu.RUnlock()

		log.Debug().Msg("Using cached firewall rules")
		return buildSyncPayload(cachedRules), nil
	}
	firewallRulesCache.mu.RUnlock()

	// Check which firewall tool is available (reuses command.go function)
	nftablesInstalled, iptablesInstalled, err := checkFirewallAvailability()
	if err != nil {
		return nil, fmt.Errorf("failed to check firewall installation: %w", err)
	}

	var chains map[string][]FirewallRuleSync

	if nftablesInstalled {
		payload, err := collectNftablesRules()
		if err != nil {
			return nil, err
		}
		chains = make(map[string][]FirewallRuleSync)
		for _, chain := range payload.Chains {
			chains[chain.Name] = chain.Rules
		}
	} else if iptablesInstalled {
		payload, err := collectIptablesRules()
		if err != nil {
			return nil, err
		}
		chains = make(map[string][]FirewallRuleSync)
		for _, chain := range payload.Chains {
			chains[chain.Name] = chain.Rules
		}
	} else {
		log.Debug().Msg("No firewall tools available, skipping firewall sync")
		return &FirewallSyncPayload{Chains: []FirewallChainSync{}}, nil
	}

	// Update cache
	firewallRulesCache.mu.Lock()
	firewallRulesCache.rules = chains
	firewallRulesCache.lastUpdate = time.Now()
	firewallRulesCache.mu.Unlock()

	return buildSyncPayload(chains), nil
}

// collectNftablesRules extracts rules from nftables
// Reverse of command.go nftables rule application
func collectNftablesRules() (*FirewallSyncPayload, error) {
	exitCode, output := runFirewallCommand([]string{"nft", "-j", "list", "ruleset"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list nftables ruleset: exit code %d", exitCode)
	}

	var nftData struct {
		Nftables []map[string]interface{} `json:"nftables"`
	}

	if err := json.Unmarshal([]byte(output), &nftData); err != nil {
		return nil, fmt.Errorf("failed to parse nftables output: %w", err)
	}

	chains := make(map[string][]FirewallRuleSync)
	tableNames := make(map[string]bool)

	// First pass: collect all table names
	for _, item := range nftData.Nftables {
		if table, ok := item["table"]; ok {
			if tableMap, ok := table.(map[string]interface{}); ok {
				if name, ok := tableMap["name"].(string); ok {
					tableNames[name] = true
				}
			}
		}
	}

	// Second pass: collect rules grouped by table (table = security group in nftables)
	currentTable := ""
	for _, item := range nftData.Nftables {
		// Track current table
		if table, ok := item["table"]; ok {
			if tableMap, ok := table.(map[string]interface{}); ok {
				if name, ok := tableMap["name"].(string); ok {
					currentTable = name
				}
			}
		}

		// Parse rules
		if rule, ok := item["rule"]; ok {
			ruleMap := rule.(map[string]interface{})
			tableName, _ := ruleMap["table"].(string)
			if tableName == "" {
				tableName = currentTable
			}

			// Only process tables we've seen in first pass
			if !tableNames[tableName] {
				continue
			}

			// Table name is the security group name in nftables
			if parsedRule, err := parseNftablesRuleToSync(ruleMap); err == nil {
				chains[tableName] = append(chains[tableName], *parsedRule)
			}
		}
	}

	return buildSyncPayload(chains), nil
}

// collectIptablesRules extracts rules from iptables
// Reverse of command.go iptables rule application
func collectIptablesRules() (*FirewallSyncPayload, error) {
	// Get all rules using iptables-save (more efficient than multiple iptables -L calls)
	exitCode, output := runFirewallCommand([]string{"iptables-save"}, 30)
	if exitCode != 0 {
		log.Debug().Msgf("Failed to run iptables-save: exit code %d", exitCode)
		return &FirewallSyncPayload{Chains: []FirewallChainSync{}}, nil
	}

	// Parse iptables-save output directly
	chains := parseIptablesSaveOutput(output)

	return buildSyncPayload(chains), nil
}

// parseNftablesRuleToSync converts nftables rule map to FirewallRuleSync
// Reverse of command.go buildNftablesRule
// If rule_id or type is missing from comment, re-creates the rule with proper metadata
func parseNftablesRuleToSync(ruleMap map[string]interface{}) (*FirewallRuleSync, error) {
	rule := &FirewallRuleSync{
		SourceCIDR: DefaultCIDR,
		Priority:   DefaultPriority,
		Protocol:   DefaultProtocol,
		Target:     DefaultTarget,
	}

	rule.Chain = ruleMap["chain"].(string)
	tableName, _ := ruleMap["table"].(string)

	// Extract comment if present
	var fullComment string
	if comment, ok := ruleMap["comment"].(string); ok {
		fullComment = comment
	}

	// Parse expressions for protocol, ports, source, target, comment, etc.
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
					if protocol, ok := left["meta"].(map[string]interface{}); ok {
						if key, ok := protocol["key"].(string); ok && key == "l4proto" {
							if right, ok := match["right"].(string); ok {
								rule.Protocol = right
							}
						}
					}
				}

				// Match ports
				if right, ok := match["right"].(float64); ok {
					port := int(right)
					if rule.PortStart == nil {
						rule.PortStart = &port
					}
				} else if right, ok := match["right"].(map[string]interface{}); ok {
					if set, ok := right["set"].([]interface{}); ok {
						// Multiport match
						var ports []string
						for _, portVal := range set {
							if p, ok := portVal.(float64); ok {
								ports = append(ports, fmt.Sprintf("%d", int(p)))
							}
						}
						if len(ports) > 0 {
							rule.Dports = strings.Join(ports, ",")
						}
					}
				}
			}

			// Match source/destination
			if match, ok := exprMap["match"].(map[string]interface{}); ok {
				if left, ok := match["left"].(map[string]interface{}); ok {
					if payload, ok := left["payload"].(map[string]interface{}); ok {
						if field, ok := payload["field"].(string); ok {
							if right, ok := match["right"].(string); ok {
								if field == "saddr" {
									rule.SourceCIDR = right
								} else if field == "daddr" {
									rule.DestinationCIDR = right
								}
							}
						}
					}
				}
			}

			// Match target/verdict
			if accept, ok := exprMap["accept"]; ok && accept != nil {
				rule.Target = "ACCEPT"
			} else if drop, ok := exprMap["drop"]; ok && drop != nil {
				rule.Target = "DROP"
			} else if reject, ok := exprMap["reject"]; ok && reject != nil {
				rule.Target = "REJECT"
			}
		}
	}

	// Check if original comment has rule_id and type
	originalRuleID, originalRuleType, existingComment := parseFirewallComment(fullComment)

	// Parse comment to extract rule_id and type, or generate new ones
	rule.RuleID, rule.RuleType = parseCommentOrGenerate(fullComment)

	// If rule_id or type was missing, re-create the rule with proper metadata
	if originalRuleID == "" || originalRuleType == "" {
		newComment := buildFirewallComment(existingComment, rule.RuleID, rule.RuleType)

		// Get rule handle from the ruleMap (available in JSON output)
		var ruleHandle string
		if handle, ok := ruleMap["handle"].(float64); ok {
			ruleHandle = fmt.Sprintf("%.0f", handle)
		}

		// Create the rule with updated comment first (for security continuity)
		if !recreateNftablesRuleWithComment(tableName, rule, newComment) {
			log.Warn().Msgf("Failed to re-create nftables rule %s with proper metadata", rule.RuleID)
			return rule, nil // Skip deletion if creation fails
		}

		// Delete the old rule using saved handle (safe because we have the exact handle)
		if ruleHandle != "" {
			deleteArgs := []string{"nft", "delete", "rule", tableName, rule.Chain, "handle", ruleHandle}
			if exitCode, _ := runFirewallCommand(deleteArgs, 10); exitCode != 0 {
				log.Warn().Msgf("Failed to delete old nftables rule with handle %s after re-creation", ruleHandle)
			} else {
				log.Debug().Msgf("Re-created nftables rule %s with proper metadata (table: %s, chain: %s)", rule.RuleID, tableName, rule.Chain)
			}
		}
	}

	return rule, nil
}

// parseIptablesSaveOutput parses iptables-save output to extract all chain rules
// Format:
// :CHAIN_NAME - [0:0]
// -A CHAIN_NAME -p protocol --dport port -s source -j TARGET -m comment --comment "..."
func parseIptablesSaveOutput(output string) map[string][]FirewallRuleSync {
	chains := make(map[string][]FirewallRuleSync)
	chainNames := make(map[string]bool)
	lines := strings.Split(output, "\n")

	// First pass: extract all chain names from chain definitions
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ":") {
			// Chain definition format: :CHAIN_NAME POLICY [packets:bytes]
			parts := strings.Fields(line)
			if len(parts) > 0 {
				chainName := strings.TrimPrefix(parts[0], ":")
				chainNames[chainName] = true
			}
		}
	}

	// Second pass: extract rules for all chains
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, comments, chain definitions, table markers
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "*") || line == "COMMIT" {
			continue
		}

		// Process both -A (append) and -I (insert) rules
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			continue
		}

		// Parse rule line
		rule := parseIptablesSaveRuleLine(line)
		if rule != nil && chainNames[rule.Chain] {
			chains[rule.Chain] = append(chains[rule.Chain], *rule)
		}
	}

	return chains
}

// parseIptablesSaveRuleLine parses a single iptables-save rule line
// Format: -A/-I CHAIN_NAME -p protocol --dport port -s source -j TARGET -m comment --comment "..."
// If rule_id or type is missing from comment, re-creates the rule with proper metadata
func parseIptablesSaveRuleLine(line string) *FirewallRuleSync {
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

	// First part is chain name
	chainName := parts[0]

	rule := &FirewallRuleSync{
		Chain:      chainName,
		SourceCIDR: DefaultCIDR,
		Priority:   DefaultPriority,
		Protocol:   DefaultProtocol,
		Target:     DefaultTarget,
	}

	// Parse arguments
	var fullComment string
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "-p", "--protocol":
			if i+1 < len(parts) {
				rule.Protocol = parts[i+1]
				i++
			}
		case "-s", "--source":
			if i+1 < len(parts) {
				rule.SourceCIDR = parts[i+1]
				i++
			}
		case "-d", "--destination":
			if i+1 < len(parts) {
				rule.DestinationCIDR = parts[i+1]
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
							rule.PortStart = &start
						}
						if end, err := strconv.Atoi(portRange[1]); err == nil {
							rule.PortEnd = &end
						}
					}
				} else {
					// Single port
					if port, err := strconv.Atoi(portStr); err == nil {
						rule.PortStart = &port
					}
				}
				i++
			}
		case "--dports":
			if i+1 < len(parts) {
				rule.Dports = parts[i+1]
				i++
			}
		case "--icmp-type":
			if i+1 < len(parts) {
				if icmpType, err := strconv.Atoi(parts[i+1]); err == nil {
					rule.ICMPType = &icmpType
				}
				i++
			}
		case "--comment":
			if i+1 < len(parts) {
				// Comment may be quoted
				comment := parts[i+1]
				comment = strings.Trim(comment, "\"")
				fullComment = comment
				i++
			}
		}
	}

	// Check if original comment has rule_id and type
	originalRuleID, originalRuleType, existingComment := parseFirewallComment(fullComment)

	// Parse comment to extract rule_id and type, or generate new ones
	rule.RuleID, rule.RuleType = parseCommentOrGenerate(fullComment)

	// If rule_id or type was missing, re-create the rule with proper metadata
	if originalRuleID == "" || originalRuleType == "" {
		newComment := buildFirewallComment(existingComment, rule.RuleID, rule.RuleType)

		// Create the rule with updated comment first (for security continuity)
		if !recreateIptablesRuleWithComment(chainName, rule, newComment) {
			log.Warn().Msgf("Failed to re-create iptables rule %s with proper metadata", rule.RuleID)
			return rule // Skip deletion if creation fails
		}

		// Delete the old rule using the old comment if it exists
		// For iptables, we need to delete using the old comment
		oldRule := *rule
		oldRule.RuleID = originalRuleID // Use original ID for deletion
		oldRule.RuleType = originalRuleType

		if err := removeIptablesRule(chainName, oldRule); err != nil {
			log.Warn().Err(err).Msgf("Failed to delete old iptables rule after re-creation")
		} else {
			log.Debug().Msgf("Re-created iptables rule %s with proper metadata (chain: %s)", rule.RuleID, chainName)
		}
	}

	return rule
}

// buildSyncPayload creates sync payload from parsed rules
func buildSyncPayload(chains map[string][]FirewallRuleSync) *FirewallSyncPayload {
	// Initialize with empty slice to avoid null in JSON serialization
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

// RemoveFirewallRulesByType removes all firewall rules of a specific type
// ruleType can be: RuleTypeUnknown (""), RuleTypeServer ("server"), or RuleTypeAlpacon ("alpacon")
// Returns the number of rules removed and any error encountered
func RemoveFirewallRulesByType(ruleType string) (int, error) {
	// Collect current firewall rules
	payload, err := collectFirewallRules()
	if err != nil {
		return 0, fmt.Errorf("failed to collect firewall rules: %w", err)
	}

	if len(payload.Chains) == 0 {
		log.Debug().Msgf("No firewall chains found for rule type: %s", ruleType)
		return 0, nil
	}

	// Check which firewall tool is available
	nftablesInstalled, iptablesInstalled, err := checkFirewallAvailability()
	if err != nil {
		return 0, fmt.Errorf("failed to check firewall availability: %w", err)
	}

	removedCount := 0

	for _, chain := range payload.Chains {
		for _, rule := range chain.Rules {
			// Skip rules that don't match the target type
			if rule.RuleType != ruleType {
				continue
			}

			// Remove the rule based on firewall backend
			var removeErr error
			if nftablesInstalled {
				removeErr = removeNftablesRule(chain.Name, rule)
			} else if iptablesInstalled {
				removeErr = removeIptablesRule(chain.Name, rule)
			}

			if removeErr != nil {
				log.Warn().Err(removeErr).Msgf("Failed to remove rule %s from chain %s", rule.RuleID, chain.Name)
			} else {
				removedCount++
				log.Debug().Msgf("Removed rule %s (type: %s) from chain %s", rule.RuleID, ruleType, chain.Name)
			}
		}
	}

	log.Info().Msgf("Removed %d firewall rules of type: %s", removedCount, ruleType)

	// Invalidate cache after removal
	firewallRulesCache.mu.Lock()
	firewallRulesCache.rules = nil
	firewallRulesCache.lastUpdate = time.Time{}
	firewallRulesCache.mu.Unlock()

	return removedCount, nil
}

// removeNftablesRule removes a specific rule from nftables
func removeNftablesRule(tableName string, rule FirewallRuleSync) error {
	// Build nft delete command
	// Format: nft delete rule <table> <chain> handle <handle>
	// Since we don't have handle, we'll use rule matching

	// Get rule handle by listing rules with handles
	exitCode, output := runFirewallCommand([]string{"nft", "-a", "list", "table", tableName}, 10)
	if exitCode != 0 {
		return fmt.Errorf("failed to list nftables table %s", tableName)
	}

	// Parse output to find matching rule handle
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for rules with our rule_id in comment
		if rule.RuleID != "" && strings.Contains(line, rule.RuleID) {
			// Extract handle number from line (format: "... # handle 123")
			if idx := strings.Index(line, "# handle "); idx != -1 {
				handleStr := strings.TrimSpace(line[idx+9:])
				handleParts := strings.Fields(handleStr)
				if len(handleParts) > 0 {
					handle := handleParts[0]

					// Delete rule by handle
					deleteArgs := []string{"nft", "delete", "rule", tableName, rule.Chain, "handle", handle}
					exitCode, _ := runFirewallCommand(deleteArgs, 10)
					if exitCode == 0 {
						return nil
					}
					return fmt.Errorf("failed to delete nftables rule handle %s", handle)
				}
			}
		}
	}

	return fmt.Errorf("rule not found in nftables table %s", tableName)
}

// removeIptablesRule removes a specific rule from iptables
func removeIptablesRule(chainName string, rule FirewallRuleSync) error {
	// Build iptables delete command by rule specification
	args := []string{"iptables", "-D", chainName}

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

	// Comment (for matching)
	if rule.RuleID != "" {
		args = append(args, "-m", "comment", "--comment")
		// Construct comment string
		comment := buildFirewallComment("", rule.RuleID, rule.RuleType)
		args = append(args, comment)
	}

	exitCode, output := runFirewallCommand(args, 10)
	if exitCode != 0 {
		return fmt.Errorf("failed to delete iptables rule from chain %s: %s", chainName, output)
	}

	return nil
}
