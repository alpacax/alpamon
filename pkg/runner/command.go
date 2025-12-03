package runner

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// CommandDispatcher interface to avoid circular import with executor package
type CommandDispatcher interface {
	Execute(ctx context.Context, command string, args *common.CommandArgs) (int, string, error)
	HasHandler(command string) bool
}

const (
	fileUploadTimeout = 60 * 10
)

func init() {
	// Inject runCmdWithOutput function into utils.firewall package
	utils.SetFirewallCommandExecutor(runCmdWithOutput)
}

func NewCommandRunner(wsClient *WebsocketClient, apiSession *scheduler.Session, command Command, data CommandData, dispatcher CommandDispatcher) *CommandRunner {
	var name string
	if command.ID != "" {
		name = fmt.Sprintf("CommandRunner-%s", strings.Split(command.ID, "-")[0])
	}

	return &CommandRunner{
		name:       name,
		command:    command,
		data:       data,
		wsClient:   wsClient,
		apiSession: apiSession,
		dispatcher: dispatcher,
	}
}

func (cr *CommandRunner) Run(ctx context.Context) error {
	var exitCode int
	var result string
	start := time.Now()

	defer func() {
		if cr.command.ID != "" {
			finURL := fmt.Sprintf(eventCommandFinURL, cr.command.ID)
			payload := &commandFin{
				Success:     exitCode == 0,
				Result:      result,
				ElapsedTime: time.Since(start).Seconds(),
			}
			scheduler.Rqueue.Post(finURL, payload, 10, time.Time{})
		}
	}()

	log.Debug().Msgf("Received command: %s > %s", cr.command.Shell, cr.command.Line)

	// Check if context is already cancelled before starting
	select {
	case <-ctx.Done():
		result = fmt.Sprintf("Command cancelled before execution: %v", ctx.Err())
		exitCode = 1
		return fmt.Errorf("command failed with exit code %d: %s", exitCode, result)
	default:
	}

	// Check if dispatcher is available
	if cr.dispatcher == nil {
		exitCode = 1
		result = "Internal error: dispatcher not initialized"
		return nil
	}

	var command string
	var args *common.CommandArgs

	switch cr.command.Shell {
	case "internal":
		fields := strings.Fields(cr.command.Line)
		if len(fields) == 0 {
			exitCode = 1
			result = "No command provided"
			return nil
		}
		command = fields[0]
		args = cr.data.ToArgs()
	case "system":
		command = common.ShellCmd.String()
		args = &common.CommandArgs{
			Command:   cr.command.Line,
			Username:  cr.command.User,
			Groupname: cr.command.Group,
			Env:       cr.command.Env,
		}
	default:
		exitCode = 1
		result = "Invalid command shell argument."
		return nil
	}

	// Check if handler exists for the command
	if !cr.dispatcher.HasHandler(command) {
		exitCode = 1
		result = fmt.Sprintf("Unknown command: %s", command)
		return nil
	}

	log.Debug().Msgf("Executing %s command: %s", cr.command.Shell, command)

	var err error
	exitCode, result, err = cr.dispatcher.Execute(ctx, command, args)
	if err != nil {
		log.Error().Err(err).Str("command", command).Msg("Command execution failed")
	}

	return nil
}

// Firewall helper functions - still needed until fully migrated to executor

func (cr *CommandRunner) applyRulesBatchWithFlush() (int, []map[string]interface{}, bool, string) {
	// Check firewall tools if needed
	_, _, err := utils.CheckFirewallTool()
	if err != nil {
		log.Error().Err(err).Msg("Failed to check firewall tools")
		return 0, nil, false, ""
	}

	// Backup current rules before applying changes
	backup, err := utils.BackupFirewallRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create firewall backup")
		return 0, nil, false, fmt.Sprintf("Failed to create backup before applying rules: %v", err)
	}
	log.Info().Msg("Created firewall backup before batch apply")

	// Apply rules
	appliedRules := 0
	var failedRules []map[string]interface{}
	var rollbackReason string
	rolledBack := false

	// Store original data to restore later
	originalChainName := cr.data.ChainName
	originalMethod := cr.data.Method
	originalChain := cr.data.Chain
	originalProtocol := cr.data.Protocol
	originalPortStart := cr.data.PortStart
	originalPortEnd := cr.data.PortEnd
	originalSource := cr.data.Source
	originalTarget := cr.data.Target
	originalDescription := cr.data.Description
	originalPriority := cr.data.Priority
	originalICMPType := cr.data.ICMPType
	originalDPorts := cr.data.DPorts

	defer func() {
		// Restore original data
		cr.data.ChainName = originalChainName
		cr.data.Method = originalMethod
		cr.data.Chain = originalChain
		cr.data.Protocol = originalProtocol
		cr.data.PortStart = originalPortStart
		cr.data.PortEnd = originalPortEnd
		cr.data.Source = originalSource
		cr.data.Target = originalTarget
		cr.data.Description = originalDescription
		cr.data.Priority = originalPriority
		cr.data.ICMPType = originalICMPType
		cr.data.DPorts = originalDPorts
	}()

	for i, ruleData := range cr.data.Rules {
		// Convert rule data to CommandData fields
		cr.data = cr.convertRuleDataToCommandData(ruleData, cr.data)

		var ruleExitCode int
		var ruleResult string

		// Check if rule has an operation field for UUID-based operations
		if operation, ok := ruleData["operation"].(string); ok && operation != "" {
			// Handle UUID-based operations (update/delete/add)
			switch operation {
			case "update":
				// Update operation requires rule_id (new) and old_rule_id (to delete)
				ruleID, hasRuleID := ruleData["rule_id"].(string)
				oldRuleID, hasOldRuleID := ruleData["old_rule_id"].(string)

				if hasRuleID && ruleID != "" && hasOldRuleID && oldRuleID != "" {
					cr.data.RuleID = ruleID
					cr.data.OldRuleID = oldRuleID
					ruleExitCode, ruleResult = cr.handleUpdateOperation()
				} else {
					ruleExitCode = 1
					ruleResult = "update operation requires both rule_id (new) and old_rule_id (to delete)"
				}
			case "delete":
				// Delete operation requires rule_id
				if ruleID, ok := ruleData["rule_id"].(string); ok && ruleID != "" {
					cr.data.RuleID = ruleID
					ruleExitCode, ruleResult = cr.handleDeleteOperation()
				} else {
					ruleExitCode = 1
					ruleResult = "delete operation requires rule_id"
				}
			case "add":
				// Add operation - use handleAddOperation for proper validation and logging
				log.Debug().Msgf("Batch add operation for rule %d/%d", i+1, len(cr.data.Rules))
				ruleExitCode, ruleResult = cr.handleAddOperation()
			default:
				ruleExitCode = 1
				ruleResult = fmt.Sprintf("unknown operation: %s", operation)
			}
		} else {
			// Default: use method-based execution (-A, -I, -R, -D)
			// This applies validation and logging via handleAddOperation
			log.Debug().Msgf("Batch method-based operation for rule %d/%d (method: %s)", i+1, len(cr.data.Rules), cr.data.Method)
			ruleExitCode, ruleResult = cr.handleAddOperation()
		}

		if ruleExitCode == 0 {
			appliedRules++
			log.Debug().Msgf("Successfully applied rule %d/%d", i+1, len(cr.data.Rules))
		} else {
			failedRules = append(failedRules, ruleData)
			log.Error().Msgf("Failed to apply rule %d/%d: %s", i+1, len(cr.data.Rules), ruleResult)

			// Rollback on failure
			rollbackReason = fmt.Sprintf("Failed to apply rule %d: %s", i+1, ruleResult)
			rollbackErr := utils.RestoreFirewallRules(backup)
			if rollbackErr != nil {
				log.Error().Err(rollbackErr).Msg("Failed to rollback firewall rules")
				rollbackReason = fmt.Sprintf("%s (rollback also failed: %v)", rollbackReason, rollbackErr)
			} else {
				log.Info().Msg("Successfully rolled back firewall rules")
			}
			rolledBack = true
			break
		}
	}

	return appliedRules, failedRules, rolledBack, rollbackReason
}

func (cr *CommandRunner) convertRuleDataToCommandData(ruleData map[string]interface{}, data CommandData) CommandData {
	// Reset all optional fields to prevent conflicts between rules in batch operations
	// This ensures each rule starts with a clean slate
	data.Method = "-A" // Default to append
	data.Chain = ""
	data.Protocol = ""
	data.PortStart = 0
	data.PortEnd = 0
	data.DPorts = nil
	data.ICMPType = ""
	data.Source = ""
	data.Destination = ""
	data.Target = ""
	data.Description = ""
	data.Priority = 0
	data.RuleType = "alpacon" // Default to alpacon type
	data.RuleID = ""
	data.OldRuleID = ""

	// Now set values from ruleData
	if chainName, ok := ruleData["chain_name"].(string); ok {
		data.ChainName = chainName
	}
	if method, ok := ruleData["method"].(string); ok {
		data.Method = method
	}
	if chain, ok := ruleData["chain"].(string); ok {
		data.Chain = chain
	}
	if protocol, ok := ruleData["protocol"].(string); ok {
		data.Protocol = protocol
	}
	if portStart, ok := ruleData["port_start"].(float64); ok {
		data.PortStart = int(portStart)
	}
	if portEnd, ok := ruleData["port_end"].(float64); ok {
		data.PortEnd = int(portEnd)
	}
	if source, ok := ruleData["source"].(string); ok {
		data.Source = source
	}
	if destination, ok := ruleData["destination"].(string); ok {
		data.Destination = destination
	}
	if target, ok := ruleData["target"].(string); ok {
		data.Target = target
	}
	if description, ok := ruleData["description"].(string); ok {
		data.Description = description
	}
	if priority, ok := ruleData["priority"].(float64); ok {
		data.Priority = int(priority)
	}
	if icmpType, ok := ruleData["icmp_type"].(string); ok {
		data.ICMPType = icmpType
	}
	if ruleType, ok := ruleData["rule_type"].(string); ok {
		data.RuleType = ruleType
	}
	if ruleID, ok := ruleData["rule_id"].(string); ok {
		data.RuleID = ruleID
	}
	if oldRuleID, ok := ruleData["old_rule_id"].(string); ok {
		data.OldRuleID = oldRuleID
	}

	// Handle dports array
	if dports, ok := ruleData["dports"].([]interface{}); ok {
		data.DPorts = make([]int, 0, len(dports))
		for _, port := range dports {
			if p, ok := port.(float64); ok {
				data.DPorts = append(data.DPorts, int(p))
			}
		}
	}

	return data
}

func (cr *CommandRunner) handleAddOperation() (int, string) {
	// Validate firewall rule data
	if err := cr.validateFirewallRuleData(); err != nil {
		return 1, err.Error()
	}

	// Execute single firewall rule
	return cr.executeSingleFirewallRule()
}

func (cr *CommandRunner) handleUpdateOperation() (int, string) {
	// First delete the old rule
	if cr.data.OldRuleID != "" {
		tempRuleID := cr.data.RuleID
		cr.data.RuleID = cr.data.OldRuleID
		exitCode, result := cr.handleDeleteOperation()
		cr.data.RuleID = tempRuleID
		if exitCode != 0 {
			return exitCode, fmt.Sprintf("Failed to delete old rule: %s", result)
		}
	}

	// Then add the new rule
	return cr.handleAddOperation()
}

func (cr *CommandRunner) handleDeleteOperation() (int, string) {
	if cr.data.RuleID == "" {
		return 1, "delete operation requires rule_id"
	}

	nftablesInstalled, _, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("Failed to check firewall tool: %v", err)
	}

	if nftablesInstalled {
		return cr.deleteNftablesRuleByID(cr.data.Chain, cr.data.RuleID)
	} else {
		return cr.deleteIptablesRuleByID(cr.data.Chain, cr.data.RuleID)
	}
}

func (cr *CommandRunner) validateFirewallRuleData() error {
	// Basic validation for required fields
	if cr.data.ChainName == "" {
		return fmt.Errorf("chain_name is required")
	}

	// Validate rule type if specified
	if cr.data.RuleType != "" && cr.data.RuleType != "alpacon" && cr.data.RuleType != "server" {
		return fmt.Errorf("invalid rule_type: %s (must be 'alpacon' or 'server')", cr.data.RuleType)
	}

	return nil
}

func (cr *CommandRunner) executeSingleFirewallRule() (int, string) {
	nftablesInstalled, _, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("Failed to check firewall tool: %v", err)
	}

	if nftablesInstalled {
		return cr.executeNftablesRule()
	} else {
		return cr.executeIptablesRule()
	}
}

func (cr *CommandRunner) executeNftablesRule() (exitCode int, result string) {
	log.Info().Msg("Using nftables for firewall management.")

	// Determine family (default to inet if not specified)
	family := cr.data.Family
	if family == "" {
		family = "inet"
	}
	log.Info().Msgf("Using nftables family: %s", family)

	// Get table name (default to "filter" if not specified)
	tableName := cr.data.Table
	if tableName == "" {
		tableName = "filter"
	}

	// Create table dynamically
	tableCmdArgs := []string{"nft", "add", "table", family, tableName}
	_, _ = runCmdWithOutput(tableCmdArgs, "root", "", nil, 60)

	// Create chain in the new table
	// cr.data.Chain now contains the complete chain name (e.g., "alpacon-web_input")
	chainName := cr.data.Chain
	chainCmdArgs := []string{"nft", "add", "chain", family, tableName, chainName}

	// Determine hook type from chain name suffix
	if strings.HasSuffix(strings.ToLower(chainName), "_input") {
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "input", "priority", "0", ";", "}")
	} else if strings.HasSuffix(strings.ToLower(chainName), "_forward") {
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}")
	} else if strings.HasSuffix(strings.ToLower(chainName), "_output") {
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "output", "priority", "0", ";", "}")
	}
	// If no suffix match, create as a regular chain (no hook)
	_, _ = runCmdWithOutput(chainCmdArgs, "root", "", nil, 60)

	// Add rule to the dynamic table/chain
	args := []string{"nft"}
	switch cr.data.Method {
	case "-A":
		args = append(args, "add")
	case "-I":
		args = append(args, "insert")
	case "-R":
		args = append(args, "replace")
	case "-D":
		args = append(args, "delete")
	}
	// cr.data.Chain already contains the complete chain name
	args = append(args, "rule", family, tableName, chainName)

	// Determine IP version keyword based on family
	ipVersion := "ip"
	icmpProtocol := "icmp"
	if family == "ip6" {
		ipVersion = "ip6"
		icmpProtocol = "icmpv6"
	}

	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" && cr.data.Source != "::/0" {
		args = append(args, ipVersion, "saddr", cr.data.Source)
	}

	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" && cr.data.Destination != "::/0" {
		args = append(args, ipVersion, "daddr", cr.data.Destination)
	}

	if cr.data.Protocol != "all" {
		if cr.data.Protocol == "icmp" || cr.data.Protocol == "icmpv6" {
			args = append(args, ipVersion, "protocol", icmpProtocol)
			if cr.data.ICMPType != "" {
				args = append(args, icmpProtocol, "type", cr.data.ICMPType)
			}
		} else if cr.data.Protocol == "tcp" || cr.data.Protocol == "udp" {
			// For TCP/UDP, use proper nftables protocol syntax
			if len(cr.data.DPorts) > 0 {
				args = append(args, cr.data.Protocol)
				var portList []string
				for _, port := range cr.data.DPorts {
					portList = append(portList, strconv.Itoa(port))
				}
				args = append(args, "dport", "{", strings.Join(portList, ","), "}")
			} else if cr.data.PortStart != 0 {
				args = append(args, cr.data.Protocol)
				// Handle single port or port range
				if cr.data.PortEnd != 0 && cr.data.PortEnd != cr.data.PortStart {
					portStr := fmt.Sprintf("%d-%d", cr.data.PortStart, cr.data.PortEnd)
					args = append(args, "dport", portStr)
				} else {
					args = append(args, "dport", strconv.Itoa(cr.data.PortStart))
				}
			} else {
				// No port specified, use ip protocol syntax
				args = append(args, ipVersion, "protocol", cr.data.Protocol)
			}
		} else {
			// For other protocols
			args = append(args, ipVersion, "protocol", cr.data.Protocol)
		}
	}

	// Add target action (accept/drop/reject)
	targetAction := strings.ToLower(cr.data.Target)
	if targetAction == "accept" || targetAction == "drop" || targetAction == "reject" {
		args = append(args, targetAction)
	} else {
		// Default action if target is not specified or invalid
		args = append(args, "accept")
	}

	// Add comment with rule_id and rule_type
	if cr.data.RuleID != "" || cr.data.RuleType != "" {
		var commentParts []string
		if cr.data.RuleID != "" {
			commentParts = append(commentParts, fmt.Sprintf("rule_id:%s", cr.data.RuleID))
		}
		if cr.data.RuleType != "" {
			commentParts = append(commentParts, fmt.Sprintf("type:%s", cr.data.RuleType))
		}
		ruleComment := strings.Join(commentParts, ",")
		args = append(args, "comment", fmt.Sprintf("\"%s\"", ruleComment))
	}

	// Log the final nftables command
	log.Info().Msgf("Executing nftables command: %s", strings.Join(args, " "))

	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

	if exitCode != 0 {
		log.Error().Msgf("nftables command failed (exit code %d): %s", exitCode, result)
		return exitCode, fmt.Sprintf("nftables error: %s", result)
	}

	log.Info().Msgf("Successfully executed nftables rule for table %s (family: %s)", tableName, family)
	return 0, fmt.Sprintf("Successfully executed rule for security group table %s (family: %s).", tableName, family)
}

// getIptablesCommand returns the appropriate iptables command based on IP family
func (cr *CommandRunner) getIptablesCommand() string {
	switch cr.data.Family {
	case "ip6":
		return "ip6tables"
	case "arp":
		return "arptables"
	case "bridge":
		return "ebtables"
	case "inet", "netdev":
		// These are nftables-only families, should not be used with iptables
		// Fall back to iptables but log a warning
		log.Warn().Msgf("Family '%s' is nftables-only, falling back to iptables", cr.data.Family)
		return "iptables"
	default:
		// Default to iptables for ip (IPv4) or unspecified family
		return "iptables"
	}
}

// executeIptablesRule executes iptables rule
func (cr *CommandRunner) executeIptablesRule() (exitCode int, result string) {
	log.Info().Msg("Using iptables for firewall management.")

	// Determine which command to use based on family
	cmd := cr.getIptablesCommand()
	log.Info().Msgf("Using %s command for family: %s", cmd, cr.data.Family)

	// cr.data.Chain now contains the complete chain name (e.g., "alpacon-web_input")
	chainName := cr.data.Chain

	// Get table parameter (default to filter if not specified)
	table := cr.data.Table
	if table == "" {
		table = "filter"
	}

	// Create chain dynamically in specified table
	chainCreateCmdArgs := []string{cmd, "-t", table, "-N", chainName}
	_, _ = runCmdWithOutput(chainCreateCmdArgs, "root", "", nil, 60)

	// Add rule to the dynamic chain
	args := []string{cmd, "-t", table, cr.data.Method, chainName}

	// Add protocol
	if cr.data.Protocol != "all" {
		args = append(args, "-p", cr.data.Protocol)
	}

	// Add source if specified
	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" {
		args = append(args, "-s", cr.data.Source)
	}

	// Add destination if specified
	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" {
		args = append(args, "-d", cr.data.Destination)
	}

	// Handle ports based on protocol
	if cr.data.Protocol == "icmp" {
		if cr.data.ICMPType != "" {
			args = append(args, "--icmp-type", cr.data.ICMPType)
		}
	} else if cr.data.Protocol == "tcp" || cr.data.Protocol == "udp" {
		// Handle multiport
		if len(cr.data.DPorts) > 0 {
			var portList []string
			for _, port := range cr.data.DPorts {
				portList = append(portList, strconv.Itoa(port))
			}
			args = append(args, "-m", "multiport", "--dports", strings.Join(portList, ","))
		} else if cr.data.PortStart != 0 {
			// Handle single port or port range
			if cr.data.PortEnd != 0 && cr.data.PortEnd != cr.data.PortStart {
				portStr := fmt.Sprintf("%d:%d", cr.data.PortStart, cr.data.PortEnd)
				args = append(args, "--dport", portStr)
			} else {
				args = append(args, "--dport", strconv.Itoa(cr.data.PortStart))
			}
		}
	}

	// Add target
	args = append(args, "-j", cr.data.Target)

	// Add comment with rule_id and rule_type
	if cr.data.RuleID != "" || cr.data.RuleType != "" {
		var commentParts []string
		if cr.data.RuleID != "" {
			commentParts = append(commentParts, fmt.Sprintf("rule_id:%s", cr.data.RuleID))
		}
		if cr.data.RuleType != "" {
			commentParts = append(commentParts, fmt.Sprintf("type:%s", cr.data.RuleType))
		}
		ruleComment := strings.Join(commentParts, ",")
		args = append(args, "-m", "comment", "--comment", ruleComment)
	}

	// Log the final command
	log.Info().Msgf("Executing %s command: %s", cmd, strings.Join(args, " "))

	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

	if exitCode != 0 {
		log.Error().Msgf("%s command failed (exit code %d): %s", cmd, exitCode, result)
		return exitCode, fmt.Sprintf("%s error: %s", cmd, result)
	}

	log.Info().Msgf("Successfully executed %s rule for chain %s", cmd, chainName)
	return 0, fmt.Sprintf("Successfully executed rule for security group chain %s.", chainName)
}

// deleteNftablesRuleByID deletes a specific nftables rule by finding its handle using rule_id in comment
func (cr *CommandRunner) deleteNftablesRuleByID(chainName, ruleID string) (exitCode int, result string) {
	log.Info().Msgf("Deleting nftables rule by ID: %s in chain %s", ruleID, chainName)

	// Get table and family from cr.data (provided by server)
	family := cr.data.Family
	table := cr.data.Table

	// Default values if not provided
	if family == "" {
		family = "inet" // Default family for nftables
	}
	if table == "" {
		table = "filter" // Default table
	}

	log.Debug().Msgf("Using nftables family: %s, table: %s, chain: %s", family, table, chainName)

	// First, list rules with handles to find the target rule
	listArgs := []string{"nft", "--handle", "list", "table", family, table}
	listExitCode, listOutput := runCmdWithOutput(listArgs, "root", "", nil, 60)

	if listExitCode != 0 {
		log.Error().Msgf("Failed to list nftables rules: %s", listOutput)
		return listExitCode, fmt.Sprintf("Failed to list rules: %s", listOutput)
	}

	// Parse the output to find rule handle in the specific chain with matching rule_id in comment
	ruleHandle := cr.findNftablesRuleHandleInChain(listOutput, chainName, ruleID)
	if ruleHandle == "" {
		log.Warn().Msgf("Rule with ID %s not found in chain %s", ruleID, chainName)
		return 1, fmt.Sprintf("Rule with ID %s not found", ruleID)
	}

	// Delete the rule using its handle
	// nftables syntax: nft delete rule <family> <table> <chain> handle <handle>
	deleteArgs := []string{"nft", "delete", "rule", family, table, chainName, "handle", ruleHandle}
	deleteExitCode, deleteOutput := runCmdWithOutput(deleteArgs, "root", "", nil, 60)

	if deleteExitCode != 0 {
		log.Error().Msgf("Failed to delete nftables rule: %s", deleteOutput)
		return deleteExitCode, fmt.Sprintf("Failed to delete rule: %s", deleteOutput)
	}

	log.Info().Msgf("Successfully deleted nftables rule with ID %s (handle %s) from chain %s", ruleID, ruleHandle, chainName)
	return 0, fmt.Sprintf("Successfully deleted rule with ID %s", ruleID)
}

// findNftablesRuleHandleInChain parses nft list output to find rule handle in a specific chain by rule_id in comment
func (cr *CommandRunner) findNftablesRuleHandleInChain(listOutput, targetChain, ruleID string) string {
	lines := strings.Split(listOutput, "\n")
	targetComment := fmt.Sprintf("rule_id:%s", ruleID)
	currentChain := ""
	inTargetChain := false

	for _, line := range lines {
		// Check for chain declarations (e.g., "chain input {", "chain output {")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "chain ") && strings.Contains(trimmed, "{") {
			// Extract chain name from "chain <name> {"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentChain = parts[1]
				inTargetChain = (currentChain == targetChain)
			}
		}

		// Only look for rules in the target chain
		if inTargetChain {
			// Look for lines containing the target comment and handle
			if strings.Contains(line, targetComment) && strings.Contains(line, "# handle") {
				// Extract handle number from the line
				if handleIndex := strings.Index(line, "# handle"); handleIndex != -1 {
					handlePart := line[handleIndex+9:] // Skip "# handle "
					handle := ""
					if spaceIndex := strings.Index(handlePart, " "); spaceIndex != -1 {
						handle = strings.TrimSpace(handlePart[:spaceIndex])
					} else {
						handle = strings.TrimSpace(handlePart)
					}
					return handle
				}
			}
		}
	}

	return ""
}

// deleteIptablesRuleByID deletes a specific iptables rule by matching rule specifications
func (cr *CommandRunner) deleteIptablesRuleByID(chainName, ruleID string) (exitCode int, result string) {
	log.Info().Msgf("Deleting iptables rule - Chain: %s, RuleID: %s", chainName, ruleID)

	// chainName now contains the complete chain name (e.g., "alpacon-web_input")
	// No need to combine with cr.data.Chain

	// Note: For iptables rule deletion with comment, we rely on rule specification matching
	// since comment format may include additional type information

	// Get table parameter (default to filter if not specified)
	table := cr.data.Table
	if table == "" {
		table = "filter"
	}

	// Build delete command with rule specifications
	cmd := cr.getIptablesCommand()
	args := []string{cmd, "-t", table, "-D", chainName}

	// Add protocol
	if cr.data.Protocol != "" && cr.data.Protocol != "all" {
		args = append(args, "-p", cr.data.Protocol)
	}

	// Add source if specified
	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" {
		args = append(args, "-s", cr.data.Source)
	}

	// Add destination if specified
	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" {
		args = append(args, "-d", cr.data.Destination)
	}

	// Handle ports based on protocol
	if cr.data.Protocol == "icmp" {
		if cr.data.ICMPType != "" {
			args = append(args, "--icmp-type", cr.data.ICMPType)
		}
	} else if cr.data.Protocol == "tcp" || cr.data.Protocol == "udp" {
		// Handle multiport
		if len(cr.data.DPorts) > 0 {
			var portList []string
			for _, port := range cr.data.DPorts {
				portList = append(portList, strconv.Itoa(port))
			}
			args = append(args, "-m", "multiport", "--dports", strings.Join(portList, ","))
		} else if cr.data.PortStart != 0 {
			// Handle single port or port range
			if cr.data.PortEnd != 0 && cr.data.PortEnd != cr.data.PortStart {
				portStr := fmt.Sprintf("%d:%d", cr.data.PortStart, cr.data.PortEnd)
				args = append(args, "--dport", portStr)
			} else {
				args = append(args, "--dport", strconv.Itoa(cr.data.PortStart))
			}
		}
	}

	// Add target
	if cr.data.Target != "" {
		args = append(args, "-j", cr.data.Target)
	}

	// Skip comment matching for deletion since the comment format may have changed
	// to include type information. Rule specification matching should be sufficient.

	// Execute delete command
	deleteExitCode, deleteOutput := runCmdWithOutput(args, "root", "", nil, 60)

	if deleteExitCode != 0 {
		log.Error().Msgf("Failed to delete iptables rule: %s", deleteOutput)
		return deleteExitCode, fmt.Sprintf("Failed to delete rule: %s", deleteOutput)
	}

	log.Info().Msgf("Successfully deleted iptables rule with ID %s", ruleID)
	return 0, fmt.Sprintf("Successfully deleted rule with ID %s", ruleID)
}
