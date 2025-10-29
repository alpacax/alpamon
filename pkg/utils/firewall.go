package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Firewall tool check state (caching)
var (
	firewallCheckMutex       sync.Mutex
	firewallCheckAttempted   bool
	firewallNftablesInstalled bool
	firewallIptablesInstalled bool
	firewallCheckError       error
)

// Default values matching alpacon-server FirewallRuleSyncSerializer
const (
	DefaultCIDR     = "0.0.0.0/0" // matches serializer default for source/destination
	DefaultPriority = 100         // matches serializer default
	DefaultProtocol = "all"
	DefaultTarget   = "ACCEPT"

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

// FirewallCommandExecutor is a function type for executing firewall commands
// This allows the runner package to inject its runCmdWithOutput function
type FirewallCommandExecutor func(args []string, user string, dir string, env map[string]string, timeout int) (exitCode int, output string)

var commandExecutor FirewallCommandExecutor

// SetFirewallCommandExecutor sets the command executor function
// This should be called from the runner package to inject its runCmdWithOutput
func SetFirewallCommandExecutor(executor FirewallCommandExecutor) {
	commandExecutor = executor
}

// runFirewallCommand executes a firewall command using the injected executor
func runFirewallCommand(args []string, timeout int) (exitCode int, output string) {
	if commandExecutor == nil {
		return 1, "firewall command executor not initialized"
	}
	return commandExecutor(args, "root", "", nil, timeout)
}

// CheckFirewallTool checks if firewall tools (nftables or iptables) are installed
// Returns (nftablesInstalled, iptablesInstalled, error)
// If neither tool is installed, returns an error without attempting installation
func CheckFirewallTool() (nftablesInstalled bool, iptablesInstalled bool, err error) {
	// Use mutex to prevent concurrent checks
	firewallCheckMutex.Lock()
	defer firewallCheckMutex.Unlock()

	// Return cached result if we've already checked
	if firewallCheckAttempted {
		return firewallNftablesInstalled, firewallIptablesInstalled, firewallCheckError
	}

	// Check if nftables is installed
	_, nftablesResult := runFirewallCommand([]string{"which", "nft"}, 0)
	nftablesInstalled = strings.Contains(nftablesResult, "nft")

	// Check if iptables is installed (only if nftables is not)
	if !nftablesInstalled {
		_, iptablesResult := runFirewallCommand([]string{"which", "iptables"}, 0)
		iptablesInstalled = strings.Contains(iptablesResult, "iptables")
	}

	// Cache the result
	firewallCheckAttempted = true
	firewallNftablesInstalled = nftablesInstalled
	firewallIptablesInstalled = iptablesInstalled

	// Return error if neither tool is installed
	if !nftablesInstalled && !iptablesInstalled {
		firewallCheckError = fmt.Errorf("firewall tool not installed: neither nftables nor iptables is available")
		return false, false, firewallCheckError
	}

	firewallCheckError = nil
	return nftablesInstalled, iptablesInstalled, nil
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

// RecreateNftablesRuleWithComment re-creates an nftables rule with updated comment
// Returns true if re-creation was successful
func RecreateNftablesRuleWithComment(tableName string, rule *FirewallRuleSync, newComment string) bool {
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

// RecreateIptablesRuleWithComment re-creates an iptables rule with updated comment
// Returns true if re-creation was successful
func RecreateIptablesRuleWithComment(chainName string, rule *FirewallRuleSync, newComment string) bool {
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

// CollectFirewallRules collects current firewall rules from the system
// This is the reverse operation of command.go firewall application logic
func CollectFirewallRules() (*FirewallSyncPayload, error) {
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

	// Check which firewall tool is available
	nftablesInstalled, iptablesInstalled, err := CheckFirewallTool()
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
		// This should never happen as CheckFirewallTool() already returns error
		// if neither tool is installed, but keep as safety fallback
		return nil, fmt.Errorf("no firewall tools available")
	}

	// Update cache
	firewallRulesCache.mu.Lock()
	firewallRulesCache.rules = chains
	firewallRulesCache.lastUpdate = time.Now()
	firewallRulesCache.mu.Unlock()

	return buildSyncPayload(chains), nil
}

// collectNftablesRules extracts rules from nftables
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

	// Second pass: collect rules grouped by table
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

			if parsedRule, err := parseNftablesRuleToSync(ruleMap); err == nil {
				chains[tableName] = append(chains[tableName], *parsedRule)
			}
		}
	}

	return buildSyncPayload(chains), nil
}

// collectIptablesRules extracts rules from iptables
func collectIptablesRules() (*FirewallSyncPayload, error) {
	exitCode, output := runFirewallCommand([]string{"iptables-save"}, 30)
	if exitCode != 0 {
		log.Debug().Msgf("Failed to run iptables-save: exit code %d", exitCode)
		return &FirewallSyncPayload{Chains: []FirewallChainSync{}}, nil
	}

	chains := parseIptablesSaveOutput(output)
	return buildSyncPayload(chains), nil
}

// parseNftablesRuleToSync converts nftables rule map to FirewallRuleSync
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
	originalRuleID, originalRuleType, existingComment := ParseFirewallComment(fullComment)

	// Parse comment to extract rule_id and type, or generate new ones
	rule.RuleID, rule.RuleType = ParseCommentOrGenerate(fullComment)

	// If rule_id or type was missing, re-create the rule with proper metadata
	if originalRuleID == "" || originalRuleType == "" {
		newComment := BuildFirewallComment(existingComment, rule.RuleID, rule.RuleType)

		// Get rule handle from the ruleMap
		var ruleHandle string
		if handle, ok := ruleMap["handle"].(float64); ok {
			ruleHandle = fmt.Sprintf("%.0f", handle)
		}

		// Create the rule with updated comment first
		if !RecreateNftablesRuleWithComment(tableName, rule, newComment) {
			log.Warn().Msgf("Failed to re-create nftables rule %s with proper metadata", rule.RuleID)
			return rule, nil
		}

		// Delete the old rule using saved handle
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
func parseIptablesSaveOutput(output string) map[string][]FirewallRuleSync {
	chains := make(map[string][]FirewallRuleSync)
	chainNames := make(map[string]bool)
	lines := strings.Split(output, "\n")

	// First pass: extract all chain names
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ":") {
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
				comment := parts[i+1]
				comment = strings.Trim(comment, "\"")
				fullComment = comment
				i++
			}
		}
	}

	// Check if original comment has rule_id and type
	originalRuleID, originalRuleType, existingComment := ParseFirewallComment(fullComment)

	// Parse comment to extract rule_id and type, or generate new ones
	rule.RuleID, rule.RuleType = ParseCommentOrGenerate(fullComment)

	// If rule_id or type was missing, re-create the rule with proper metadata
	if originalRuleID == "" || originalRuleType == "" {
		newComment := BuildFirewallComment(existingComment, rule.RuleID, rule.RuleType)

		// Create the rule with updated comment first
		if !RecreateIptablesRuleWithComment(chainName, rule, newComment) {
			log.Warn().Msgf("Failed to re-create iptables rule %s with proper metadata", rule.RuleID)
			return rule
		}

		// Delete the old rule
		oldRule := *rule
		oldRule.RuleID = originalRuleID
		oldRule.RuleType = originalRuleType

		if err := RemoveIptablesRule(chainName, oldRule); err != nil {
			log.Warn().Err(err).Msgf("Failed to delete old iptables rule after re-creation")
		} else {
			log.Debug().Msgf("Re-created iptables rule %s with proper metadata (chain: %s)", rule.RuleID, chainName)
		}
	}

	return rule
}

// buildSyncPayload creates sync payload from parsed rules
func buildSyncPayload(chains map[string][]FirewallRuleSync) *FirewallSyncPayload {
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
func RemoveFirewallRulesByType(ruleType string) (int, error) {
	// Create backup before removing rules
	backup, err := BackupFirewallRules()
	if err != nil {
		return 0, fmt.Errorf("failed to backup firewall rules: %w", err)
	}

	payload, err := CollectFirewallRules()
	if err != nil {
		return 0, fmt.Errorf("failed to collect firewall rules: %w", err)
	}

	if len(payload.Chains) == 0 {
		log.Debug().Msgf("No firewall chains found for rule type: %s", ruleType)
		return 0, nil
	}

	nftablesInstalled, iptablesInstalled, err := CheckFirewallTool()
	if err != nil {
		return 0, fmt.Errorf("failed to check firewall availability: %w", err)
	}

	removedCount := 0

	for _, chain := range payload.Chains {
		for _, rule := range chain.Rules {
			if rule.RuleType != ruleType {
				continue
			}

			var removeErr error
			if nftablesInstalled {
				removeErr = RemoveNftablesRule(chain.Name, rule)
			} else if iptablesInstalled {
				removeErr = RemoveIptablesRule(chain.Name, rule)
			}

			if removeErr != nil {
				log.Error().Err(removeErr).Msgf("Failed to remove rule %s from chain %s, restoring backup", rule.RuleID, chain.Name)
				if restoreErr := RestoreFirewallRules(backup); restoreErr != nil {
					log.Error().Err(restoreErr).Msg("Failed to restore backup after removal failure")
					return removedCount, fmt.Errorf("failed to remove rule and restore failed: %w", restoreErr)
				}
				return removedCount, fmt.Errorf("failed to remove rule %s, backup restored: %w", rule.RuleID, removeErr)
			}

			removedCount++
			log.Debug().Msgf("Removed rule %s (type: %s) from chain %s", rule.RuleID, ruleType, chain.Name)
		}
	}

	log.Info().Msgf("Removed %d firewall rules of type: %s", removedCount, ruleType)

	// Invalidate cache
	firewallRulesCache.mu.Lock()
	firewallRulesCache.rules = nil
	firewallRulesCache.lastUpdate = time.Time{}
	firewallRulesCache.mu.Unlock()

	return removedCount, nil
}

// RemoveNftablesRule removes a specific rule from nftables
func RemoveNftablesRule(tableName string, rule FirewallRuleSync) error {
	exitCode, output := runFirewallCommand([]string{"nft", "-a", "list", "table", tableName}, 10)
	if exitCode != 0 {
		return fmt.Errorf("failed to list nftables table %s", tableName)
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if rule.RuleID != "" && strings.Contains(line, rule.RuleID) {
			if idx := strings.Index(line, "# handle "); idx != -1 {
				handleStr := strings.TrimSpace(line[idx+9:])
				handleParts := strings.Fields(handleStr)
				if len(handleParts) > 0 {
					handle := handleParts[0]
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

// RemoveIptablesRule removes a specific rule from iptables
func RemoveIptablesRule(chainName string, rule FirewallRuleSync) error {
	args := []string{"iptables", "-D", chainName}

	if rule.Protocol != "" && rule.Protocol != DefaultProtocol {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.SourceCIDR != "" && rule.SourceCIDR != DefaultCIDR {
		args = append(args, "-s", rule.SourceCIDR)
	}

	if rule.DestinationCIDR != "" && rule.DestinationCIDR != DefaultCIDR {
		args = append(args, "-d", rule.DestinationCIDR)
	}

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

	if rule.Protocol == "icmp" && rule.ICMPType != nil {
		args = append(args, "--icmp-type", fmt.Sprintf("%d", *rule.ICMPType))
	}

	if rule.Target != "" {
		args = append(args, "-j", rule.Target)
	}

	if rule.RuleID != "" {
		args = append(args, "-m", "comment", "--comment")
		comment := BuildFirewallComment("", rule.RuleID, rule.RuleType)
		args = append(args, comment)
	}

	exitCode, output := runFirewallCommand(args, 10)
	if exitCode != 0 {
		return fmt.Errorf("failed to delete iptables rule from chain %s: %s", chainName, output)
	}

	return nil
}

// ReorderNftablesChains reorders nftables INPUT chain jump rules
func ReorderNftablesChains(chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting nftables chain reordering")

	// Backup current ruleset
	backup, err := BackupFirewallRules()
	if err != nil {
		return nil, fmt.Errorf("failed to backup nftables ruleset: %w", err)
	}

	// Get current INPUT chain rules with handles
	exitCode, output := runFirewallCommand([]string{"nft", "-a", "list", "chain", "inet", "filter", "INPUT"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list INPUT chain rules")
	}

	// Parse and find alpacon jump rule handles
	jumpHandles := []string{}
	lines := strings.Split(output, "\n")

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

	// Delete old jump rules
	for _, handle := range jumpHandles {
		exitCode, errOutput := runFirewallCommand(
			[]string{"nft", "delete", "rule", "inet", "filter", "INPUT", "handle", handle},
			10,
		)
		if exitCode != 0 {
			log.Error().Msgf("Failed to delete rule handle %s: %s", handle, errOutput)
			if err := RestoreFirewallRules(backup); err != nil {
				log.Error().Err(err).Msg("Failed to restore backup after delete failure")
			}
			return nil, fmt.Errorf("failed to delete rule handle %s", handle)
		}
		log.Debug().Msgf("Deleted rule handle: %s", handle)
	}

	// Add jump rules in new order
	for _, chainName := range chainNames {
		exitCode, errOutput := runFirewallCommand(
			[]string{"nft", "add", "rule", "inet", "filter", "INPUT", "jump", chainName},
			10,
		)
		if exitCode != 0 {
			log.Error().Msgf("Failed to add jump rule for chain %s: %s", chainName, errOutput)
			if err := RestoreFirewallRules(backup); err != nil {
				log.Error().Err(err).Msg("Failed to restore backup after add failure")
			}
			return nil, fmt.Errorf("failed to add jump rule for chain %s", chainName)
		}
		log.Debug().Msgf("Added jump rule for chain: %s", chainName)
	}

	return map[string]interface{}{
		"reordered_chains": chainNames,
		"deleted_rules":    len(jumpHandles),
	}, nil
}

// ReorderIptablesChains reorders iptables INPUT chain jump rules
func ReorderIptablesChains(chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting iptables chain reordering")

	// Backup current rules
	backup, err := BackupFirewallRules()
	if err != nil {
		return nil, fmt.Errorf("failed to backup iptables rules: %w", err)
	}

	// Get current INPUT chain rules
	exitCode, output := runFirewallCommand([]string{"iptables", "-L", "INPUT", "--line-numbers", "-n"}, 30)
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list INPUT chain rules")
	}

	// Find alpacon jump rule line numbers
	jumpLines := []int{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		for _, chainName := range chainNames {
			if parts[1] == chainName || (len(parts) > 2 && parts[2] == chainName) {
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

	// Sort in reverse order
	for i := 0; i < len(jumpLines); i++ {
		for j := i + 1; j < len(jumpLines); j++ {
			if jumpLines[i] < jumpLines[j] {
				jumpLines[i], jumpLines[j] = jumpLines[j], jumpLines[i]
			}
		}
	}

	// Delete old jump rules
	for _, lineNum := range jumpLines {
		exitCode, errOutput := runFirewallCommand(
			[]string{"iptables", "-D", "INPUT", fmt.Sprintf("%d", lineNum)},
			10,
		)
		if exitCode != 0 {
			log.Error().Msgf("Failed to delete rule at line %d: %s", lineNum, errOutput)
			if err := RestoreFirewallRules(backup); err != nil {
				log.Error().Err(err).Msg("Failed to restore backup after delete failure")
			}
			return nil, fmt.Errorf("failed to delete rule at line %d", lineNum)
		}
		log.Debug().Msgf("Deleted rule at line: %d", lineNum)
	}

	// Add jump rules in new order
	for _, chainName := range chainNames {
		exitCode, errOutput := runFirewallCommand(
			[]string{"iptables", "-A", "INPUT", "-j", chainName},
			10,
		)
		if exitCode != 0 {
			log.Error().Msgf("Failed to add jump rule for chain %s: %s", chainName, errOutput)
			if err := RestoreFirewallRules(backup); err != nil {
				log.Error().Err(err).Msg("Failed to restore backup after add failure")
			}
			return nil, fmt.Errorf("failed to add jump rule for chain %s", chainName)
		}
		log.Debug().Msgf("Added jump rule for chain: %s", chainName)
	}

	return map[string]interface{}{
		"reordered_chains": chainNames,
		"deleted_rules":    len(jumpLines),
	}, nil
}

// BackupFirewallRules creates a backup of current firewall rules
// Returns the backup string and error
func BackupFirewallRules() (string, error) {
	nftablesInstalled, iptablesInstalled, err := CheckFirewallTool()
	if err != nil {
		return "", fmt.Errorf("failed to check firewall installation: %w", err)
	}

	if nftablesInstalled {
		exitCode, output := runFirewallCommand([]string{"nft", "list", "ruleset"}, 30)
		if exitCode != 0 {
			return "", fmt.Errorf("failed to backup nftables ruleset: exit code %d", exitCode)
		}
		log.Debug().Msg("Created nftables backup")
		return output, nil
	} else if iptablesInstalled {
		exitCode, output := runFirewallCommand([]string{"iptables-save"}, 30)
		if exitCode != 0 {
			return "", fmt.Errorf("failed to backup iptables rules: exit code %d", exitCode)
		}
		log.Debug().Msg("Created iptables backup")
		return output, nil
	}

	return "", fmt.Errorf("no firewall tools available for backup")
}

// RestoreFirewallRules restores firewall rules from backup string
// Automatically detects the firewall type and uses appropriate restore method
func RestoreFirewallRules(backup string) error {
	if backup == "" {
		return fmt.Errorf("empty backup provided")
	}

	nftablesInstalled, iptablesInstalled, err := CheckFirewallTool()
	if err != nil {
		return fmt.Errorf("failed to check firewall installation: %w", err)
	}

	if nftablesInstalled {
		return restoreNftablesBackup(backup)
	} else if iptablesInstalled {
		return restoreIptablesBackup(backup)
	}

	return fmt.Errorf("no firewall tools available for restore")
}

// restoreNftablesBackup restores nftables ruleset from backup string
func restoreNftablesBackup(backup string) error {
	log.Warn().Msg("Restoring nftables backup")

	tmpFile := fmt.Sprintf("/tmp/nft-backup-%d-%d.nft", os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create nftables backup temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	if _, err := f.WriteString(backup); err != nil {
		f.Close()
		return fmt.Errorf("failed to write nftables backup: %w", err)
	}
	f.Close()

	runFirewallCommand([]string{"nft", "flush", "ruleset"}, 10)
	exitCode, output := runFirewallCommand([]string{"nft", "-f", tmpFile}, 10)

	if exitCode != 0 {
		return fmt.Errorf("failed to restore nftables backup: %s", output)
	}

	log.Info().Msg("Successfully restored nftables backup")
	return nil
}

// restoreIptablesBackup restores iptables rules from backup string
func restoreIptablesBackup(backup string) error {
	log.Warn().Msg("Restoring iptables backup")

	tmpFile := fmt.Sprintf("/tmp/iptables-backup-%d-%d.rules", os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create iptables backup temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	if _, err := f.WriteString(backup); err != nil {
		f.Close()
		return fmt.Errorf("failed to write iptables backup: %w", err)
	}
	f.Close()

	exitCode, output := runFirewallCommand([]string{"iptables-restore", tmpFile}, 10)

	if exitCode != 0 {
		return fmt.Errorf("failed to restore iptables backup: %s", output)
	}

	log.Info().Msg("Successfully restored iptables backup")
	return nil
}

// RestoreNftablesBackup restores nftables ruleset from backup
// Deprecated: Use RestoreFirewallRules instead
func RestoreNftablesBackup(backup string) {
	if err := restoreNftablesBackup(backup); err != nil {
		log.Error().Err(err).Msg("Failed to restore nftables backup")
	}
}

// RestoreIptablesBackup restores iptables rules from backup
// Deprecated: Use RestoreFirewallRules instead
func RestoreIptablesBackup(backup string) {
	if err := restoreIptablesBackup(backup); err != nil {
		log.Error().Err(err).Msg("Failed to restore iptables backup")
	}
}
