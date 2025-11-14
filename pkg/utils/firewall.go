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
	firewallCheckMutex        sync.Mutex
	firewallCheckAttempted    bool
	firewallNftablesInstalled bool
	firewallIptablesInstalled bool
	firewallCheckError        error

	// Feature flag to disable automatic rule recreation
	// Set to true to prevent conflicts with ufw/firewalld and rule_id changes
	disableRuleRecreation = true

	// Temporary flag to disable all firewall functionality
	// Set to true to completely disable alpacon firewall management
	firewallFunctionalityDisabled = false

	// Firewall backend detection cache
	firewallBackendMutex     sync.Mutex
	firewallBackendAttempted bool
	cachedFirewallBackend    *BackendInfo
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

// chainMetadata holds table and family information for a chain
type chainMetadata struct {
	table  string
	family string
}

// FirewallChainSync represents a firewall chain for sync payload
type FirewallChainSync struct {
	Name   string             `json:"name"`
	Table  string             `json:"table"`  // filter, nat, mangle, raw, security
	Family string             `json:"family"` // ip, ip6, inet, arp, bridge, netdev
	Rules  []FirewallRuleSync `json:"rules"`
}

// FirewallRuleSync represents a single firewall rule for sync
// This matches the alpacon-server FirewallRuleSyncSerializer format
type FirewallRuleSync struct {
	Chain           string `json:"chain"`
	Table           string `json:"table"`  // filter, nat, mangle, raw, security
	Family          string `json:"family"` // ip, ip6, inet, arp, bridge, netdev
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
	BackendInfo *BackendInfo        `json:"backend_info,omitempty"` // Backend information
	Chains      []FirewallChainSync `json:"chains"`
}

// Note: Firewall rules caching removed to ensure real-time rule synchronization
// and prevent stale data issues during rapid rule updates

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

// IsFirewallDisabled checks if firewall functionality is disabled
func IsFirewallDisabled() bool {
	return firewallFunctionalityDisabled
}

// BackendInfo contains firewall backend information
type BackendInfo struct {
	Type    string `json:"type"`    // iptables, nftables, firewalld, ufw
	Version string `json:"version"` // version string
}

// DetectFirewallBackend detects the active firewall backend and version
// Priority: firewalld > ufw > nftables > iptables
// This provides comprehensive backend information for sync protocol
func DetectFirewallBackend(force bool) *BackendInfo {
	// Use mutex to prevent concurrent checks
	firewallBackendMutex.Lock()
	defer firewallBackendMutex.Unlock()

	// Return cached result if not forcing and already checked
	if !force && firewallBackendAttempted && cachedFirewallBackend != nil {
		return cachedFirewallBackend
	}

	var result *BackendInfo
	log.Info().Msgf("Detecting firewall backend")

	// 1. Check firewalld first (highest priority)
	if isServiceActive("firewalld") {
		version := getFirewalldVersion()
		log.Info().Msgf("Detected firewalld backend (version: %s)", version)
		result = &BackendInfo{
			Type:    "firewalld",
			Version: version,
		}
	} else if isUFWActive() {
		// 2. Check ufw
		version := getUFWVersion()
		log.Info().Msgf("Detected ufw backend (version: %s)", version)
		result = &BackendInfo{
			Type:    "ufw",
			Version: version,
		}
	} else if hasNftablesRules() {
		// 3. Check nftables (has rules)
		version := getNftablesVersion()
		log.Info().Msgf("Detected nftables backend (version: %s)", version)
		result = &BackendInfo{
			Type:    "nftables",
			Version: version,
		}
	} else if hasIptablesAvailable() {
		// 4. Fallback to iptables if available
		version := getIptablesVersion()
		log.Info().Msgf("Detected iptables backend (version: %s)", version)
		result = &BackendInfo{
			Type:    "iptables",
			Version: version,
		}
	} else {
		log.Warn().Msg("No firewall backend detected")
		result = &BackendInfo{
			Type:    "none",
			Version: "",
		}
	}

	// Cache the result
	firewallBackendAttempted = true
	cachedFirewallBackend = result

	return result
}

// isServiceActive checks if a systemd service is active
func isServiceActive(serviceName string) bool {
	exitCode, output := runFirewallCommand([]string{"systemctl", "is-active", serviceName}, 5)
	return exitCode == 0 && strings.TrimSpace(output) == "active"
}

// getFirewalldVersion retrieves firewalld version
func getFirewalldVersion() string {
	exitCode, output := runFirewallCommand([]string{"firewall-cmd", "--version"}, 5)
	if exitCode == 0 {
		return strings.TrimSpace(output)
	}
	return "unknown"
}

// isUFWActive checks if ufw is active
func isUFWActive() bool {
	exitCode, output := runFirewallCommand([]string{"ufw", "status"}, 5)
	return exitCode == 0 && strings.Contains(strings.ToLower(output), "status: active")
}

// getUFWVersion retrieves ufw version
func getUFWVersion() string {
	exitCode, output := runFirewallCommand([]string{"ufw", "version"}, 5)
	if exitCode == 0 {
		// Extract version number from output like "ufw 0.36"
		parts := strings.Fields(output)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "unknown"
}

// hasNftablesRules checks if nftables has any rules
func hasNftablesRules() bool {
	exitCode, output := runFirewallCommand([]string{"nft", "list", "ruleset"}, 5)
	if exitCode != 0 {
		return false
	}

	// Check for actual rules (not just empty tables)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Rules typically start with protocol, source, destination, etc.
		if strings.HasPrefix(line, "ip ") || strings.HasPrefix(line, "tcp ") ||
			strings.HasPrefix(line, "udp ") || strings.HasPrefix(line, "icmp ") ||
			strings.HasPrefix(line, "meta ") || strings.HasPrefix(line, "counter ") {
			return true
		}
	}
	return false
}

// getNftablesVersion retrieves nftables version
func getNftablesVersion() string {
	exitCode, output := runFirewallCommand([]string{"nft", "--version"}, 5)
	if exitCode == 0 {
		// Extract version from output like "nftables v1.0.5 (Lester Gooch)"
		parts := strings.Fields(output)
		if len(parts) >= 2 {
			// Remove 'v' prefix if present
			version := parts[1]
			return strings.TrimPrefix(version, "v")
		}
	}
	return "unknown"
}

// hasIptablesAvailable checks if iptables is available
func hasIptablesAvailable() bool {
	exitCode, _ := runFirewallCommand([]string{"which", "iptables"}, 5)
	return exitCode == 0
}

// getIptablesVersion retrieves iptables version
func getIptablesVersion() string {
	exitCode, output := runFirewallCommand([]string{"iptables", "--version"}, 5)
	if exitCode == 0 {
		// Extract version from output like "iptables v1.8.7 (nf_tables)"
		parts := strings.Fields(output)
		if len(parts) >= 2 {
			// Remove 'v' prefix if present
			version := parts[1]
			return strings.TrimPrefix(version, "v")
		}
	}
	return "unknown"
}

// CheckFirewallTool checks if firewall tools (nftables or iptables) are installed
// and detects which backend to use based on existing rules
// Returns (nftablesInstalled, iptablesInstalled, error)
func CheckFirewallTool() (nftablesInstalled bool, iptablesInstalled bool, err error) {
	// Use mutex to prevent concurrent checks
	firewallCheckMutex.Lock()
	defer firewallCheckMutex.Unlock()

	// TEMPORARY FIX: Always re-detect, ignore cache
	// TODO: Remove this after fixing cache invalidation issue
	// if firewallCheckAttempted {
	// 	return firewallNftablesInstalled, firewallIptablesInstalled, firewallCheckError
	// }

	// Detect backend based on existing rules
	backend := detectFirewallBackend()

	if backend == "iptables" {
		nftablesInstalled = false
		iptablesInstalled = true
		log.Info().Msg("Using iptables backend (existing iptables rules detected)")
	} else if backend == "nftables" {
		nftablesInstalled = true
		iptablesInstalled = false
		log.Info().Msg("Using nftables backend (no iptables rules found)")
	} else {
		// Neither backend available
		firewallCheckError = fmt.Errorf("firewall tool not installed: neither nftables nor iptables is available")
		firewallCheckAttempted = true
		return false, false, firewallCheckError
	}

	// Cache the result
	firewallCheckAttempted = true
	firewallNftablesInstalled = nftablesInstalled
	firewallIptablesInstalled = iptablesInstalled
	firewallCheckError = nil

	return nftablesInstalled, iptablesInstalled, nil
}

// detectFirewallBackend detects which firewall backend to use based on existing rules
// Returns "iptables", "nftables", or "none"
func detectFirewallBackend() string {
	// 1. Try iptables-save to check for existing iptables rules
	exitCode, output := runFirewallCommand([]string{"iptables-save"}, 10)

	if exitCode == 0 {
		// Count actual rules (lines starting with -A or -I)
		ruleCount := 0
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
				ruleCount++
			}
		}

		if ruleCount > 0 {
			log.Debug().Msgf("Found %d iptables rules", ruleCount)
			return "iptables"
		}

		// iptables-save succeeded but no rules - check if nft is available
		exitCode, _ := runFirewallCommand([]string{"which", "nft"}, 5)
		if exitCode == 0 {
			log.Debug().Msg("No iptables rules, nft available")
			return "nftables"
		}

		// Only iptables available, no nft
		log.Debug().Msg("No iptables rules, nft not available, defaulting to iptables")
		return "iptables"
	}

	// 2. iptables-save failed, try fallback with iptables -S
	exitCode, output = runFirewallCommand([]string{"iptables", "-S"}, 10)
	if exitCode == 0 {
		// Check for rules (iptables -S output starts with -P, -A, -I, etc)
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
				log.Debug().Msg("Found iptables rules via iptables -S")
				return "iptables"
			}
		}
	}

	// 3. No iptables rules found, check if nft is available
	exitCode, _ = runFirewallCommand([]string{"which", "nft"}, 5)
	if exitCode == 0 {
		log.Debug().Msg("No iptables rules, using nftables")
		return "nftables"
	}

	// 4. Neither iptables nor nft available
	log.Warn().Msg("No firewall backend available")
	return "none"
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
func RecreateNftablesRuleWithComment(family string, table string, rule *FirewallRuleSync, newComment string) bool {
	// Step 1: List rules in JSON format to find exact matching rule
	listArgs := []string{"nft", "-j", "list", "chain", family, table, rule.Chain}
	exitCode, output := runFirewallCommand(listArgs, 10)
	if exitCode != 0 {
		log.Debug().Msgf("Failed to list chain %s in table %s %s", rule.Chain, family, table)
		return false
	}

	// Parse JSON output
	var nftOutput map[string]interface{}
	if err := json.Unmarshal([]byte(output), &nftOutput); err != nil {
		log.Debug().Msgf("Failed to parse nftables JSON output: %v", err)
		return false
	}

	// Find matching rule without comment and collect all handles for position tracking
	var matchingHandle int64 = -1
	var handles []int64
	var rulePosition int = 0

	if nftables, ok := nftOutput["nftables"].([]interface{}); ok {
		for _, item := range nftables {
			if ruleMap, ok := item.(map[string]interface{}); ok {
				if ruleData, ok := ruleMap["rule"].(map[string]interface{}); ok {
					// Collect all handles to track positions
					if handle, ok := ruleData["handle"].(float64); ok {
						handles = append(handles, int64(handle))

						// Skip if rule has comment
						if comment, hasComment := ruleData["comment"]; hasComment && comment != "" {
							continue
						}

						// Check if this rule matches our criteria
						if matchesNftablesJSONRule(ruleData, rule) {
							matchingHandle = int64(handle)
							rulePosition = len(handles) // Current position in the chain
						}
					}
				}
			}
		}
	}

	// If no matching rule found, return false
	if matchingHandle == -1 {
		log.Debug().Msgf("No matching rule found without comment, skipping recreation")
		return false
	}

	// Step 2: Insert new rule at the same position
	// Find the handle to insert after (position - 1)
	var insertArgs []string
	if rulePosition > 1 && rulePosition <= len(handles) {
		// Insert after the previous rule
		insertAfterHandle := handles[rulePosition-2] // -2 because: -1 for previous, -1 for 0-based index
		insertArgs = []string{"nft", "add", "rule", family, table, rule.Chain, "position", fmt.Sprintf("%d", insertAfterHandle)}
	} else {
		// Insert at the beginning
		insertArgs = []string{"nft", "insert", "rule", family, table, rule.Chain}
	}

	// Add rule specifications
	if rule.Protocol != "" && rule.Protocol != DefaultProtocol {
		insertArgs = append(insertArgs, "meta", "l4proto", rule.Protocol)
	}
	if rule.SourceCIDR != "" && rule.SourceCIDR != DefaultCIDR {
		insertArgs = append(insertArgs, "ip", "saddr", rule.SourceCIDR)
	}
	if rule.DestinationCIDR != "" && rule.DestinationCIDR != DefaultCIDR {
		insertArgs = append(insertArgs, "ip", "daddr", rule.DestinationCIDR)
	}
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		if rule.Dports != "" {
			ports := strings.Split(rule.Dports, ",")
			insertArgs = append(insertArgs, rule.Protocol, "dport", "{")
			insertArgs = append(insertArgs, ports...)
			insertArgs = append(insertArgs, "}")
		} else if rule.PortStart != nil {
			if rule.PortEnd != nil && *rule.PortEnd != *rule.PortStart {
				insertArgs = append(insertArgs, rule.Protocol, "dport", fmt.Sprintf("%d-%d", *rule.PortStart, *rule.PortEnd))
			} else {
				insertArgs = append(insertArgs, rule.Protocol, "dport", fmt.Sprintf("%d", *rule.PortStart))
			}
		}
	}
	if rule.Protocol == "icmp" && rule.ICMPType != nil {
		insertArgs = append(insertArgs, "icmp", "type", fmt.Sprintf("%d", *rule.ICMPType))
	}
	insertArgs = append(insertArgs, strings.ToLower(rule.Target))
	if newComment != "" {
		insertArgs = append(insertArgs, "comment", fmt.Sprintf("\"%s\"", newComment))
	}

	// Execute the insert command
	exitCode, _ = runFirewallCommand(insertArgs, 10)
	if exitCode != 0 {
		log.Warn().Msgf("Failed to insert new rule with comment for rule_id %s", rule.RuleID)
		return false
	}

	// Step 3: Delete the old rule using its handle
	deleteArgs := []string{"nft", "delete", "rule", family, table, rule.Chain, "handle", fmt.Sprintf("%d", matchingHandle)}
	exitCode, _ = runFirewallCommand(deleteArgs, 10)
	if exitCode != 0 {
		log.Warn().Msgf("Failed to delete old rule (handle %d) for rule_id %s", matchingHandle, rule.RuleID)
		// Rule was added, so operation partially succeeded
		return true
	}

	log.Debug().Msgf("Successfully recreated rule with comment for rule_id %s", rule.RuleID)
	return true
}

// matchesNftablesJSONRule checks if a JSON rule data matches our FirewallRuleSync
func matchesNftablesJSONRule(ruleData map[string]interface{}, rule *FirewallRuleSync) bool {
	expr, ok := ruleData["expr"].([]interface{})
	if !ok {
		return false
	}

	// Check what we need to match
	needProtocol := rule.Protocol != "" && rule.Protocol != DefaultProtocol
	needSource := rule.SourceCIDR != "" && rule.SourceCIDR != DefaultCIDR
	needDest := rule.DestinationCIDR != "" && rule.DestinationCIDR != DefaultCIDR
	needPort := rule.PortStart != nil || rule.Dports != ""

	// Track what we found
	hasProtocol := !needProtocol
	hasSource := !needSource
	hasDest := !needDest
	hasPort := !needPort
	hasTarget := false

	for _, e := range expr {
		exprMap, ok := e.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for match expressions
		if match, ok := exprMap["match"].(map[string]interface{}); ok {
			if left, ok := match["left"].(map[string]interface{}); ok {
				// Check meta matches (protocol)
				if meta, ok := left["meta"].(map[string]interface{}); ok {
					if key, ok := meta["key"].(string); ok && key == "l4proto" {
						if right, ok := match["right"].(string); ok && right == rule.Protocol {
							hasProtocol = true
						}
					}
				}

				// Check payload matches (IP addresses, ports)
				if payload, ok := left["payload"].(map[string]interface{}); ok {
					protocol, _ := payload["protocol"].(string)
					field, _ := payload["field"].(string)

					if protocol == "ip" {
						if field == "saddr" && needSource {
							if right, ok := match["right"].(map[string]interface{}); ok {
								if prefix, ok := right["prefix"].(map[string]interface{}); ok {
									addr, _ := prefix["addr"].(string)
									length, _ := prefix["len"].(float64)
									if fmt.Sprintf("%s/%d", addr, int(length)) == rule.SourceCIDR {
										hasSource = true
									}
								}
							} else if right, ok := match["right"].(string); ok && right == rule.SourceCIDR {
								hasSource = true
							}
						}
						if field == "daddr" && needDest {
							if right, ok := match["right"].(map[string]interface{}); ok {
								if prefix, ok := right["prefix"].(map[string]interface{}); ok {
									addr, _ := prefix["addr"].(string)
									length, _ := prefix["len"].(float64)
									if fmt.Sprintf("%s/%d", addr, int(length)) == rule.DestinationCIDR {
										hasDest = true
									}
								}
							} else if right, ok := match["right"].(string); ok && right == rule.DestinationCIDR {
								hasDest = true
							}
						}
					}

					if (protocol == "tcp" || protocol == "udp") && field == "dport" && needPort {
						if right, ok := match["right"].(map[string]interface{}); ok {
							// Check for port range
							if rangeMap, ok := right["range"].([]interface{}); ok && len(rangeMap) == 2 {
								start, _ := rangeMap[0].(float64)
								end, _ := rangeMap[1].(float64)
								if rule.PortStart != nil && rule.PortEnd != nil {
									if int(start) == *rule.PortStart && int(end) == *rule.PortEnd {
										hasPort = true
									}
								}
							}
							// Check for port set
							if set, ok := right["set"].([]interface{}); ok {
								if rule.Dports != "" {
									ports := strings.Split(rule.Dports, ",")
									if len(set) == len(ports) {
										// Simple check - could be improved to check actual values
										hasPort = true
									}
								}
							}
						} else if right, ok := match["right"].(float64); ok {
							// Single port
							if rule.PortStart != nil && rule.PortEnd == nil {
								if int(right) == *rule.PortStart {
									hasPort = true
								}
							}
						}
					}
				}
			}
		}

		// Check for verdict (accept/drop/reject)
		target := strings.ToLower(rule.Target)
		if _, ok := exprMap[target]; ok {
			hasTarget = true
		}
	}

	return hasProtocol && hasSource && hasDest && hasPort && hasTarget
}

// getIptablesCommand returns the appropriate iptables command based on IP family
func getIptablesCommand(family string) string {
	switch family {
	case "ip6":
		return "ip6tables"
	case "arp":
		return "arptables"
	case "bridge":
		return "ebtables"
	case "inet", "netdev":
		// These are nftables-only families, fall back to iptables
		log.Warn().Msgf("Family '%s' is nftables-only, falling back to iptables", family)
		return "iptables"
	default:
		// Default to iptables for ip (IPv4) or unspecified family
		return "iptables"
	}
}

// RecreateIptablesRuleWithComment re-creates an iptables rule with updated comment
// Returns true if re-creation was successful
func RecreateIptablesRuleWithComment(tableName string, chainName string, rule *FirewallRuleSync, newComment string) bool {
	// Determine which command to use based on family
	cmd := getIptablesCommand(rule.Family)

	// Step 1: Find the position of the existing rule without comment
	// Build a pattern that will match the rule in iptables -L output
	// We'll check for the key components that define the rule

	// Build list command with table parameter
	listArgs := []string{cmd}
	if tableName != "" && tableName != "filter" {
		listArgs = append(listArgs, "-t", tableName)
	}
	listArgs = append(listArgs, "-L", chainName, "--line-numbers", "-n", "-v")
	exitCode, output := runFirewallCommand(listArgs, 10)

	var rulePosition int
	if exitCode == 0 {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			// Skip header lines
			if strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "num") || strings.TrimSpace(line) == "" {
				continue
			}

			// Skip rules that already have rule_id
			if strings.Contains(line, "rule_id:") {
				continue
			}

			// Check if this line contains our rule components
			// Target should be case-insensitive match
			targetMatch := rule.Target == "" || strings.Contains(strings.ToLower(line), strings.ToLower(rule.Target))

			// Protocol match
			protocolMatch := rule.Protocol == "" || rule.Protocol == "all" ||
				strings.Contains(line, " "+rule.Protocol+" ") || strings.Contains(line, " "+rule.Protocol+"/")

			// Source match (check for exact match in the line)
			sourceMatch := rule.SourceCIDR == "" || rule.SourceCIDR == "0.0.0.0/0" ||
				strings.Contains(line, " "+rule.SourceCIDR+" ") || strings.Contains(line, " "+rule.SourceCIDR+"\t")

			// Destination match
			destMatch := rule.DestinationCIDR == "" || rule.DestinationCIDR == "0.0.0.0/0" ||
				strings.Contains(line, " "+rule.DestinationCIDR+" ") || strings.Contains(line, " "+rule.DestinationCIDR+"\t") ||
				strings.HasSuffix(line, " "+rule.DestinationCIDR)

			if targetMatch && protocolMatch && sourceMatch && destMatch {
				// Extract line number
				fields := strings.Fields(line)
				if len(fields) > 0 {
					fmt.Sscanf(fields[0], "%d", &rulePosition)
					log.Debug().Msgf("Found matching rule at position %d", rulePosition)
					break
				}
			}
		}
	}

	// Step 2: Insert the new rule with comment at the found position (or position 1 if not found)
	insertPosition := rulePosition
	if insertPosition == 0 {
		insertPosition = 1  // Default to top if not found
		log.Debug().Msgf("Could not find existing rule position, inserting at position 1")
	}

	insertArgs := buildIptablesRuleArgs(cmd, tableName, "-I", chainName, rule, newComment)
	// Insert at the specific position
	// Calculate base index (cmd + optional -t table + method + chain = 2/4 args)
	baseIdx := 2
	if tableName != "" && tableName != "filter" {
		baseIdx = 4
	}
	insertArgs = append(insertArgs[:baseIdx], append([]string{fmt.Sprintf("%d", insertPosition)}, insertArgs[baseIdx:]...)...)

	exitCode, _ = runFirewallCommand(insertArgs, 10)
	if exitCode != 0 {
		log.Warn().Msgf("Failed to insert new rule with comment for rule_id %s at position %d", rule.RuleID, insertPosition)
		return false
	}

	// Step 3: Try to delete the old rule (now at position+1 if we found it)
	if rulePosition > 0 {
		// Delete by position (it's now at position+1 after our insert)
		deleteArgs := []string{cmd}
		if tableName != "" && tableName != "filter" {
			deleteArgs = append(deleteArgs, "-t", tableName)
		}
		deleteArgs = append(deleteArgs, "-D", chainName, fmt.Sprintf("%d", rulePosition+1))
		deleteExitCode, _ := runFirewallCommand(deleteArgs, 10)

		if deleteExitCode != 0 {
			// Fallback: try to delete by spec
			deleteArgs = buildIptablesRuleArgs(cmd, tableName, "-D", chainName, rule, "")
			runFirewallCommand(deleteArgs, 10)
		}
	} else {
		// Try to delete by spec if we didn't find the position
		deleteArgs := buildIptablesRuleArgs(cmd, tableName, "-D", chainName, rule, "")
		runFirewallCommand(deleteArgs, 10)
	}

	log.Debug().Msgf("Successfully updated comment for rule %s in chain %s", rule.RuleID, chainName)
	return true
}

// buildIptablesRuleArgs builds iptables command arguments for a rule
func buildIptablesRuleArgs(cmd, tableName, method, chainName string, rule *FirewallRuleSync, comment string) []string {
	args := []string{cmd}

	// Add table parameter if specified and not the default filter table
	if tableName != "" && tableName != "filter" {
		args = append(args, "-t", tableName)
	}

	args = append(args, method, chainName)

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

	// Comment
	if comment != "" {
		args = append(args, "-m", "comment", "--comment", comment)
	}

	return args
}

// CollectFirewallRules collects current firewall rules from the system
// This is the reverse operation of command.go firewall application logic
// Includes backend detection information in the sync payload
// Accepts backendInfo to avoid re-detection; if nil, will detect automatically
func CollectFirewallRules(backendInfo *BackendInfo) (*FirewallSyncPayload, error) {
	// Use provided backendInfo or detect if not provided
	if backendInfo == nil {
		// TEMPORARY FIX: Always force re-detection
		backendInfo = DetectFirewallBackend(true)
	}
	log.Debug().Msgf("Detected firewall backend: %s (version: %s)", backendInfo.Type, backendInfo.Version)

	// Check which firewall tool is available for rule collection
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

	payload := buildSyncPayload(chains)
	payload.BackendInfo = backendInfo
	return payload, nil
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

	// Map: chainKey (table:family:chain) -> chainMetadata (table, family)
	chainMeta := make(map[string]chainMetadata)

	// Map: chainKey -> rules
	chainRules := make(map[string][]FirewallRuleSync)

	// First pass: collect table and chain information with family
	currentTable := ""
	currentFamily := ""
	for _, item := range nftData.Nftables {
		// Track current table and its family
		if table, ok := item["table"]; ok {
			if tableMap, ok := table.(map[string]interface{}); ok {
				if name, ok := tableMap["name"].(string); ok {
					currentTable = name
				}
				if family, ok := tableMap["family"].(string); ok {
					currentFamily = family
				}
			}
		}

		// Track chains and their metadata
		if chain, ok := item["chain"]; ok {
			if chainMap, ok := chain.(map[string]interface{}); ok {
				chainName, _ := chainMap["name"].(string)
				table, _ := chainMap["table"].(string)
				family, _ := chainMap["family"].(string)

				// Use current table/family if not specified
				if table == "" {
					table = currentTable
				}
				if family == "" {
					family = currentFamily
				}

				if chainName != "" && table != "" && family != "" {
					chainKey := fmt.Sprintf("%s:%s:%s", table, family, chainName)
					chainMeta[chainKey] = chainMetadata{table: table, family: family}
				}
			}
		}
	}

	// Second pass: collect rules with table/family info
	currentTable = ""
	currentFamily = ""
	for _, item := range nftData.Nftables {
		// Track current table
		if table, ok := item["table"]; ok {
			if tableMap, ok := table.(map[string]interface{}); ok {
				if name, ok := tableMap["name"].(string); ok {
					currentTable = name
				}
				if family, ok := tableMap["family"].(string); ok {
					currentFamily = family
				}
			}
		}

		// Parse rules
		if rule, ok := item["rule"]; ok {
			ruleMap := rule.(map[string]interface{})
			tableName, _ := ruleMap["table"].(string)
			family, _ := ruleMap["family"].(string)

			// Use current table/family if not specified in rule
			if tableName == "" {
				tableName = currentTable
			}
			if family == "" {
				family = currentFamily
			}

			if parsedRule, err := parseNftablesRuleToSync(ruleMap, tableName, family); err == nil {
				chainKey := fmt.Sprintf("%s:%s:%s", parsedRule.Table, parsedRule.Family, parsedRule.Chain)
				chainRules[chainKey] = append(chainRules[chainKey], *parsedRule)
			}
		}
	}

	return buildSyncPayloadWithMetadata(chainRules, chainMeta), nil
}

// collectIptablesRules extracts rules from all iptables families (IPv4, IPv6, ARP, bridge)
func collectIptablesRules() (*FirewallSyncPayload, error) {
	// Use chainKey format: "table:family:chain" to keep families separate
	allChainRules := make(map[string][]FirewallRuleSync)
	chainMeta := make(map[string]chainMetadata)
	anySuccess := false

	// Collect IPv4 rules (iptables)
	exitCode, output := runFirewallCommand([]string{"iptables-save"}, 30)
	if exitCode == 0 {
		ipv4ChainRules, ipv4ChainMeta := parseIptablesSaveOutputWithKeys(output, "ip")
		for chainKey, rules := range ipv4ChainRules {
			allChainRules[chainKey] = rules
		}
		for chainKey, meta := range ipv4ChainMeta {
			chainMeta[chainKey] = meta
		}
		log.Debug().Msgf("Collected %d IPv4 chains from iptables", len(ipv4ChainRules))
		anySuccess = true
	} else {
		log.Debug().Msgf("Failed to run iptables-save: exit code %d", exitCode)
	}

	// Collect IPv6 rules (ip6tables)
	exitCode6, output6 := runFirewallCommand([]string{"ip6tables-save"}, 30)
	if exitCode6 == 0 {
		ipv6ChainRules, ipv6ChainMeta := parseIptablesSaveOutputWithKeys(output6, "ip6")
		for chainKey, rules := range ipv6ChainRules {
			allChainRules[chainKey] = rules
		}
		for chainKey, meta := range ipv6ChainMeta {
			chainMeta[chainKey] = meta
		}
		log.Debug().Msgf("Collected %d IPv6 chains from ip6tables", len(ipv6ChainRules))
		anySuccess = true
	} else {
		log.Debug().Msgf("Failed to run ip6tables-save: exit code %d", exitCode6)
	}

	// Collect ARP rules (arptables) if available
	exitCodeArp, outputArp := runFirewallCommand([]string{"arptables-save"}, 30)
	if exitCodeArp == 0 {
		arpChainRules, arpChainMeta := parseIptablesSaveOutputWithKeys(outputArp, "arp")
		for chainKey, rules := range arpChainRules {
			allChainRules[chainKey] = rules
		}
		for chainKey, meta := range arpChainMeta {
			chainMeta[chainKey] = meta
		}
		log.Debug().Msgf("Collected %d ARP chains from arptables", len(arpChainRules))
		anySuccess = true
	} else {
		log.Debug().Msgf("arptables-save not available or failed: exit code %d", exitCodeArp)
	}

	// Collect bridge rules (ebtables) if available
	exitCodeEb, outputEb := runFirewallCommand([]string{"ebtables-save"}, 30)
	if exitCodeEb == 0 {
		ebChainRules, ebChainMeta := parseIptablesSaveOutputWithKeys(outputEb, "bridge")
		for chainKey, rules := range ebChainRules {
			allChainRules[chainKey] = rules
		}
		for chainKey, meta := range ebChainMeta {
			chainMeta[chainKey] = meta
		}
		log.Debug().Msgf("Collected %d bridge chains from ebtables", len(ebChainRules))
		anySuccess = true
	} else {
		log.Debug().Msgf("ebtables-save not available or failed: exit code %d", exitCodeEb)
	}

	// Return empty payload if all failed
	if !anySuccess {
		return &FirewallSyncPayload{Chains: []FirewallChainSync{}}, nil
	}

	return buildSyncPayloadWithMetadata(allChainRules, chainMeta), nil
}

// parseNftablesRuleToSync converts nftables rule map to FirewallRuleSync
func parseNftablesRuleToSync(ruleMap map[string]interface{}, table, family string) (*FirewallRuleSync, error) {
	rule := &FirewallRuleSync{
		SourceCIDR: DefaultCIDR,
		Priority:   DefaultPriority,
		Protocol:   DefaultProtocol,
		Target:     DefaultTarget,
		Table:      table,
		Family:     family,
	}

	rule.Chain = ruleMap["chain"].(string)

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
	// DISABLED: This can conflict with ufw/firewalld
	if !disableRuleRecreation && (originalRuleID == "" || originalRuleType == "") {
		newComment := BuildFirewallComment(existingComment, rule.RuleID, rule.RuleType)

		// Get rule handle from the ruleMap
		var ruleHandle string
		if handle, ok := ruleMap["handle"].(float64); ok {
			ruleHandle = fmt.Sprintf("%.0f", handle)
		}

		// Create the rule with updated comment first
		if !RecreateNftablesRuleWithComment(family, table, rule, newComment) {
			log.Warn().Msgf("Failed to re-create nftables rule %s with proper metadata", rule.RuleID)
			return rule, nil
		}

		// Delete the old rule using saved handle
		if ruleHandle != "" {
			deleteArgs := []string{"nft", "delete", "rule", family, table, rule.Chain, "handle", ruleHandle}
			if exitCode, _ := runFirewallCommand(deleteArgs, 10); exitCode != 0 {
				log.Warn().Msgf("Failed to delete old nftables rule with handle %s after re-creation", ruleHandle)
			} else {
				log.Debug().Msgf("Re-created nftables rule %s with proper metadata (table: %s %s, chain: %s)", rule.RuleID, family, table, rule.Chain)
			}
		}
	}

	return rule, nil
}

// parseIptablesSaveOutputWithKeys parses iptables-save output with unique chain keys
// Returns: map[chainKey]rules and map[chainKey]metadata
// chainKey format: "table:family:chain" (e.g., "filter:ip:INPUT", "nat:ip6:PREROUTING")
func parseIptablesSaveOutputWithKeys(output string, family string) (map[string][]FirewallRuleSync, map[string]chainMetadata) {
	chainRules := make(map[string][]FirewallRuleSync)
	chainMeta := make(map[string]chainMetadata)
	chainNames := make(map[string]bool)
	lines := strings.Split(output, "\n")

	// Track current table (default: filter)
	currentTable := "filter"

	// First pass: extract all chain names with their tables
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track table markers (e.g., "*filter", "*nat", "*mangle")
		if strings.HasPrefix(line, "*") {
			currentTable = strings.TrimPrefix(line, "*")
		}

		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				chainName := strings.TrimPrefix(parts[0], ":")
				chainKey := fmt.Sprintf("%s:%s:%s", currentTable, family, chainName)
				chainNames[chainName] = true
				chainMeta[chainKey] = chainMetadata{
					table:  currentTable,
					family: family,
				}
			}
		}
	}

	// Second pass: extract rules for all chains
	currentTable = "filter"
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track table markers
		if strings.HasPrefix(line, "*") {
			currentTable = strings.TrimPrefix(line, "*")
		}

		// Skip empty lines, comments, chain definitions, table markers
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "*") || line == "COMMIT" {
			continue
		}

		// Process both -A (append) and -I (insert) rules
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			continue
		}

		// Parse rule line with current table and family
		rule := parseIptablesSaveRuleLine(line, currentTable, family)
		if rule != nil && chainNames[rule.Chain] {
			chainKey := fmt.Sprintf("%s:%s:%s", currentTable, family, rule.Chain)
			chainRules[chainKey] = append(chainRules[chainKey], *rule)
		}
	}

	return chainRules, chainMeta
}

// parseIptablesSaveOutput parses iptables-save output to extract all chain rules
// family: "ip" for iptables, "ip6" for ip6tables
// Deprecated: Use parseIptablesSaveOutputWithKeys for proper table/family separation
func parseIptablesSaveOutput(output string, family string) map[string][]FirewallRuleSync {
	chains := make(map[string][]FirewallRuleSync)
	chainNames := make(map[string]bool)
	lines := strings.Split(output, "\n")

	// Track current table (default: filter)
	currentTable := "filter"

	// First pass: extract all chain names
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track table markers (e.g., "*filter", "*nat", "*mangle")
		if strings.HasPrefix(line, "*") {
			currentTable = strings.TrimPrefix(line, "*")
		}

		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				chainName := strings.TrimPrefix(parts[0], ":")
				chainNames[chainName] = true
			}
		}
	}

	// Second pass: extract rules for all chains
	currentTable = "filter"
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track table markers
		if strings.HasPrefix(line, "*") {
			currentTable = strings.TrimPrefix(line, "*")
		}

		// Skip empty lines, comments, chain definitions, table markers
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "*") || line == "COMMIT" {
			continue
		}

		// Process both -A (append) and -I (insert) rules
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			continue
		}

		// Parse rule line with current table and family
		rule := parseIptablesSaveRuleLine(line, currentTable, family)
		if rule != nil && chainNames[rule.Chain] {
			chains[rule.Chain] = append(chains[rule.Chain], *rule)
		}
	}

	return chains
}

// parseIptablesSaveRuleLine parses a single iptables-save rule line
// family: "ip" for iptables, "ip6" for ip6tables
func parseIptablesSaveRuleLine(line string, table string, family string) *FirewallRuleSync {
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
		Table:      table,
		Family:     family, // "ip" or "ip6"
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
				rule.Target = parts[i+1]  // Keep original case, don't convert to uppercase
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
	// DISABLED: This can conflict with ufw/firewalld
	if !disableRuleRecreation && (originalRuleID == "" || originalRuleType == "") {
		newComment := BuildFirewallComment(existingComment, rule.RuleID, rule.RuleType)

		// Create the rule with updated comment first
		if !RecreateIptablesRuleWithComment(rule.Table, chainName, rule, newComment) {
			log.Warn().Msgf("Failed to re-create iptables rule %s with proper metadata", rule.RuleID)
			return rule
		}

		// Delete the old rule with original comment
		oldRule := *rule
		oldRule.RuleID = originalRuleID
		oldRule.RuleType = originalRuleType
		// Preserve the full original comment for exact matching
		oldComment := BuildFirewallComment(existingComment, originalRuleID, originalRuleType)

		if err := RemoveIptablesRuleWithComment(chainName, oldRule, oldComment); err != nil {
			log.Warn().Err(err).Msgf("Failed to delete old iptables rule after re-creation")
		} else {
			log.Debug().Msgf("Re-created iptables rule %s with proper metadata (chain: %s)", rule.RuleID, chainName)
		}
	}

	return rule
}

// buildSyncPayloadWithMetadata creates sync payload with table/family metadata
// chainRules: map[chainKey] -> rules (chainKey format: "table:family:chain")
// chainMeta: map[chainKey] -> metadata (table, family)
func buildSyncPayloadWithMetadata(chainRules map[string][]FirewallRuleSync, chainMeta map[string]chainMetadata) *FirewallSyncPayload {
	chainsList := make([]FirewallChainSync, 0)

	for chainKey, rules := range chainRules {
		if len(rules) == 0 {
			continue
		}

		// Parse chainKey: "table:family:chain"
		parts := strings.Split(chainKey, ":")
		if len(parts) != 3 {
			continue
		}

		table, family, chainName := parts[0], parts[1], parts[2]

		chainsList = append(chainsList, FirewallChainSync{
			Name:   chainName,
			Table:  table,
			Family: family,
			Rules:  rules,
		})
	}

	return &FirewallSyncPayload{
		Chains: chainsList,
	}
}

// buildSyncPayload creates sync payload from parsed rules (legacy, for iptables)
// For iptables, table is always "filter" and family is "ip"
func buildSyncPayload(chains map[string][]FirewallRuleSync) *FirewallSyncPayload {
	chainsList := make([]FirewallChainSync, 0)

	for name, rules := range chains {
		if len(rules) > 0 {
			// For iptables, default to filter table and ip family
			table := "filter"
			family := "ip"

			// Extract from first rule if available
			if len(rules) > 0 && rules[0].Table != "" {
				table = rules[0].Table
			}
			if len(rules) > 0 && rules[0].Family != "" {
				family = rules[0].Family
			}

			chainsList = append(chainsList, FirewallChainSync{
				Name:   name,
				Table:  table,
				Family: family,
				Rules:  rules,
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

	payload, err := CollectFirewallRules(nil)
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
	// Determine which command to use based on family
	cmd := getIptablesCommand(rule.Family)

	args := []string{cmd, "-D", chainName}

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

// RemoveIptablesRuleWithComment removes an iptables rule using exact comment match
// This is used when we need to delete the old rule after recreating it with updated comment
func RemoveIptablesRuleWithComment(chainName string, rule FirewallRuleSync, fullComment string) error {
	// Determine which command to use based on family
	cmd := getIptablesCommand(rule.Family)

	args := []string{cmd, "-D", chainName}

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

	// Use the exact comment provided (includes description + metadata)
	if fullComment != "" {
		args = append(args, "-m", "comment", "--comment", fullComment)
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
// Note: This function uses iptables (IPv4) by default. For IPv6 support, use ReorderIptablesChainsByFamily
func ReorderIptablesChains(chainNames []string) (map[string]interface{}, error) {
	log.Debug().Msg("Starting iptables chain reordering")

	// Use default IPv4 (iptables)
	cmd := getIptablesCommand("ip")

	// Backup current rules
	backup, err := BackupFirewallRules()
	if err != nil {
		return nil, fmt.Errorf("failed to backup iptables rules: %w", err)
	}

	// Get current INPUT chain rules
	exitCode, output := runFirewallCommand([]string{cmd, "-L", "INPUT", "--line-numbers", "-n"}, 30)
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
			[]string{cmd, "-D", "INPUT", fmt.Sprintf("%d", lineNum)},
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
			[]string{cmd, "-A", "INPUT", "-j", chainName},
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
		// Backup both IPv4 and IPv6 rules
		var backupBuilder strings.Builder

		// IPv4 backup
		exitCode4, output4 := runFirewallCommand([]string{"iptables-save"}, 30)
		if exitCode4 == 0 {
			backupBuilder.WriteString("# IPv4 Rules\n")
			backupBuilder.WriteString(output4)
			backupBuilder.WriteString("\n")
			log.Debug().Msg("Created IPv4 iptables backup")
		} else {
			log.Warn().Msgf("Failed to backup IPv4 iptables rules: exit code %d", exitCode4)
		}

		// IPv6 backup
		exitCode6, output6 := runFirewallCommand([]string{"ip6tables-save"}, 30)
		if exitCode6 == 0 {
			backupBuilder.WriteString("# IPv6 Rules\n")
			backupBuilder.WriteString(output6)
			log.Debug().Msg("Created IPv6 ip6tables backup")
		} else {
			log.Warn().Msgf("Failed to backup IPv6 ip6tables rules: exit code %d", exitCode6)
		}

		// Return error only if both failed
		if exitCode4 != 0 && exitCode6 != 0 {
			return "", fmt.Errorf("failed to backup both IPv4 and IPv6 iptables rules")
		}

		return backupBuilder.String(), nil
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
// Handles both IPv4 and IPv6 rules
func restoreIptablesBackup(backup string) error {
	log.Warn().Msg("Restoring iptables backup")

	// Split backup into IPv4 and IPv6 sections
	lines := strings.Split(backup, "\n")
	var ipv4Lines, ipv6Lines []string
	var currentSection string

	for _, line := range lines {
		if strings.HasPrefix(line, "# IPv4 Rules") {
			currentSection = "ipv4"
			continue
		} else if strings.HasPrefix(line, "# IPv6 Rules") {
			currentSection = "ipv6"
			continue
		}

		if currentSection == "ipv4" && line != "" {
			ipv4Lines = append(ipv4Lines, line)
		} else if currentSection == "ipv6" && line != "" {
			ipv6Lines = append(ipv6Lines, line)
		}
	}

	var restoreErrors []string

	// Restore IPv4 rules
	if len(ipv4Lines) > 0 {
		ipv4Backup := strings.Join(ipv4Lines, "\n")
		tmpFile4 := fmt.Sprintf("/tmp/iptables-backup-%d-%d.rules", os.Getpid(), time.Now().UnixNano())
		f4, err := os.OpenFile(tmpFile4, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("IPv4: failed to create temp file: %v", err))
		} else {
			defer os.Remove(tmpFile4)
			if _, err := f4.WriteString(ipv4Backup); err != nil {
				f4.Close()
				restoreErrors = append(restoreErrors, fmt.Sprintf("IPv4: failed to write backup: %v", err))
			} else {
				f4.Close()
				exitCode, output := runFirewallCommand([]string{"iptables-restore", tmpFile4}, 10)
				if exitCode != 0 {
					restoreErrors = append(restoreErrors, fmt.Sprintf("IPv4: failed to restore: %s", output))
				} else {
					log.Info().Msg("Successfully restored IPv4 iptables backup")
				}
			}
		}
	}

	// Restore IPv6 rules
	if len(ipv6Lines) > 0 {
		ipv6Backup := strings.Join(ipv6Lines, "\n")
		tmpFile6 := fmt.Sprintf("/tmp/ip6tables-backup-%d-%d.rules", os.Getpid(), time.Now().UnixNano())
		f6, err := os.OpenFile(tmpFile6, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("IPv6: failed to create temp file: %v", err))
		} else {
			defer os.Remove(tmpFile6)
			if _, err := f6.WriteString(ipv6Backup); err != nil {
				f6.Close()
				restoreErrors = append(restoreErrors, fmt.Sprintf("IPv6: failed to write backup: %v", err))
			} else {
				f6.Close()
				exitCode, output := runFirewallCommand([]string{"ip6tables-restore", tmpFile6}, 10)
				if exitCode != 0 {
					restoreErrors = append(restoreErrors, fmt.Sprintf("IPv6: failed to restore: %s", output))
				} else {
					log.Info().Msg("Successfully restored IPv6 ip6tables backup")
				}
			}
		}
	}

	// Return error if any restore failed
	if len(restoreErrors) > 0 {
		return fmt.Errorf("failed to restore iptables backup: %s", strings.Join(restoreErrors, "; "))
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
