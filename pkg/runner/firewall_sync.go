package runner

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

// Default values matching alpacon-server FirewallRuleSyncSerializer
const (
	DefaultSourceCIDR = "0.0.0.0/0" // matches serializer default
	DefaultPriority   = 100          // matches serializer default
	DefaultProtocol   = "all"
	DefaultTarget     = "ACCEPT"
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
	currentTable := ""

	// First pass: collect all table names
	for _, item := range nftData.Nftables {
		if table, ok := item["table"]; ok {
			if tableMap, ok := table.(map[string]interface{}); ok {
				if name, ok := tableMap["name"].(string); ok {
					tableNames[name] = true
					currentTable = name
				}
			}
		}
	}

	// Second pass: collect rules grouped by table (table = security group in nftables)
	currentTable = ""
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
	chains := make(map[string][]FirewallRuleSync)

	// Get all rules using iptables-save (more efficient than multiple iptables -L calls)
	exitCode, output := runFirewallCommand([]string{"iptables-save"}, 30)
	if exitCode != 0 {
		log.Debug().Msgf("Failed to run iptables-save: exit code %d", exitCode)
		return &FirewallSyncPayload{Chains: []FirewallChainSync{}}, nil
	}

	// Parse iptables-save output directly
	chains = parseIptablesSaveOutput(output)

	return buildSyncPayload(chains), nil
}

// parseNftablesRuleToSync converts nftables rule map to FirewallRuleSync
// Reverse of command.go buildNftablesRule
func parseNftablesRuleToSync(ruleMap map[string]interface{}) (*FirewallRuleSync, error) {
	rule := &FirewallRuleSync{
		SourceCIDR: DefaultSourceCIDR,
		Priority:   DefaultPriority,
		Protocol:   DefaultProtocol,
		Target:     DefaultTarget,
	}

	// Extract chain name
	if chain, ok := ruleMap["chain"].(string); ok {
		rule.Chain = normalizeChainType(chain)
	}

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

	// Parse comment to extract rule_id and type, or generate new ones
	rule.RuleID, rule.RuleType = parseCommentOrGenerate(fullComment)

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
		SourceCIDR: DefaultSourceCIDR,
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

	// Parse comment to extract rule_id and type, or generate new ones
	rule.RuleID, rule.RuleType = parseCommentOrGenerate(fullComment)

	return rule
}

// buildSyncPayload creates sync payload from parsed rules
func buildSyncPayload(chains map[string][]FirewallRuleSync) *FirewallSyncPayload {
	var chainsList []FirewallChainSync

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

// syncFirewallRules sends firewall rules to alpacon-server
// This is called after server commit to sync existing firewall configuration
func syncFirewallRules() error {
	firewallData, err := collectFirewallRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to collect firewall rules")
		return err
	}

	if len(firewallData.Chains) == 0 {
		log.Debug().Msg("No firewall rules to sync")
		return nil
	}

	// Send to alpacon-server
	jsonData, err := json.Marshal(firewallData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal firewall data")
		return err
	}

	const firewallSyncURL = "/api/firewall/agent/sync/"
	scheduler.Rqueue.Post(firewallSyncURL, jsonData, 80, time.Time{})

	log.Info().Msgf("Queued firewall sync with %d chains", len(firewallData.Chains))

	// Update firewall rules with generated UUIDs in comments
	// This ensures subsequent syncs will find the same UUIDs
	if err := updateFirewallRuleComments(firewallData); err != nil {
		log.Warn().Err(err).Msg("Failed to update firewall rule comments, will retry on next sync")
	}

	return nil
}

// updateFirewallRuleComments updates existing firewall rules with UUID comments
// This allows subsequent syncs to reuse the same UUIDs
func updateFirewallRuleComments(payload *FirewallSyncPayload) error {
	nftablesInstalled, iptablesInstalled, err := checkFirewallAvailability()
	if err != nil {
		return fmt.Errorf("failed to check firewall availability: %w", err)
	}

	if nftablesInstalled {
		return updateNftablesRuleComments(payload)
	} else if iptablesInstalled {
		return updateIptablesRuleComments(payload)
	}

	return nil
}

// updateNftablesRuleComments updates nftables rules with UUID comments
func updateNftablesRuleComments(payload *FirewallSyncPayload) error {
	// nftables doesn't support in-place comment updates easily
	// For now, we'll log and skip - comments will be added when rules are recreated
	log.Debug().Msg("nftables comment updates not yet implemented, UUIDs will be added on rule recreation")
	return nil
}

// updateIptablesRuleComments updates iptables rules with UUID comments
func updateIptablesRuleComments(payload *FirewallSyncPayload) error {
	for _, chain := range payload.Chains {
		chainName := chain.Name

		// Get current rules to find ones without UUIDs
		exitCode, output := runFirewallCommand([]string{"iptables-save", "-t", "filter"}, 10)
		if exitCode != 0 {
			continue
		}

		lines := strings.Split(output, "\n")
		ruleIndex := 0

		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Only process rules for this chain
			if !strings.HasPrefix(line, "-A "+chainName) {
				continue
			}

			// Check if rule already has rule_id in comment
			if strings.Contains(line, "rule_id:") {
				ruleIndex++
				continue
			}

			// Find matching rule in payload
			if ruleIndex >= len(chain.Rules) {
				break
			}

			rule := chain.Rules[ruleIndex]
			ruleIndex++

			// Skip if no UUID was generated
			if rule.RuleID == "" || rule.RuleType == "" {
				continue
			}

			// Build comment to add
			newComment := buildFirewallComment("", rule.RuleID, rule.RuleType)

			// Recreate the rule with comment using iptables-restore
			// This is safer than trying to modify in-place
			deleteArgs := []string{"iptables", "-D", chainName, fmt.Sprintf("%d", ruleIndex)}
			insertArgs := buildIptablesArgsFromRule(chainName, rule, newComment)

			// Delete old rule
			exitCode, _ := runFirewallCommand(deleteArgs, 10)
			if exitCode != 0 {
				log.Debug().Msgf("Failed to delete iptables rule %d in chain %s for comment update", ruleIndex, chainName)
				continue
			}

			// Insert rule with comment at same position
			exitCode, _ = runFirewallCommand(insertArgs, 10)
			if exitCode != 0 {
				log.Warn().Msgf("Failed to insert iptables rule %d with comment in chain %s", ruleIndex, chainName)
			} else {
				log.Debug().Msgf("Updated comment for iptables rule %d in chain %s with UUID %s", ruleIndex, chainName, rule.RuleID)
			}
		}
	}

	return nil
}

// buildIptablesArgsFromRule builds iptables command args from FirewallRuleSync
func buildIptablesArgsFromRule(chainName string, rule FirewallRuleSync, comment string) []string {
	args := []string{"iptables", "-A", chainName}

	// Protocol
	if rule.Protocol != "" && rule.Protocol != "all" {
		args = append(args, "-p", rule.Protocol)
	}

	// Source CIDR
	if rule.SourceCIDR != "" && rule.SourceCIDR != "0.0.0.0/0" {
		args = append(args, "-s", rule.SourceCIDR)
	}

	// Destination CIDR
	if rule.DestinationCIDR != "" && rule.DestinationCIDR != "0.0.0.0/0" {
		args = append(args, "-d", rule.DestinationCIDR)
	}

	// Handle ports
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		if rule.Dports != "" {
			// Multiport
			args = append(args, "-m", "multiport", "--dports", rule.Dports)
		} else if rule.PortStart != nil {
			// Single port or port range
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

	// Comment
	if comment != "" {
		args = append(args, "-m", "comment", "--comment", comment)
	}

	return args
}
