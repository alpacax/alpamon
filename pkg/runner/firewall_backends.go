package runner

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// handleFirewalldOperation handles firewall operations for firewalld backend
func (cr *CommandRunner) handleFirewalldOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewalld operation: %s, Zone: %s", cr.data.Operation, cr.data.Zone)

	switch cr.data.Operation {
	case "add":
		return cr.handleFirewalldAdd()
	case "delete":
		return cr.handleFirewalldDelete()
	case "batch":
		return cr.handleFirewalldBatch()
	case "flush":
		return cr.handleFirewalldFlush()
	case "update":
		return cr.handleFirewalldUpdate()
	default:
		return 1, fmt.Sprintf("firewalld: Unsupported operation '%s'", cr.data.Operation)
	}
}

// handleUFWOperation handles firewall operations for ufw backend
func (cr *CommandRunner) handleUFWOperation() (exitCode int, result string) {
	log.Info().Msgf("UFW operation: %s, Direction: %s", cr.data.Operation, cr.data.Direction)

	switch cr.data.Operation {
	case "add":
		return cr.handleUFWAdd()
	case "delete":
		return cr.handleUFWDelete()
	case "batch":
		return cr.handleUFWBatch()
	case "flush":
		return cr.handleUFWFlush()
	case "update":
		return cr.handleUFWUpdate()
	default:
		return 1, fmt.Sprintf("ufw: Unsupported operation '%s'", cr.data.Operation)
	}
}

// handleFirewalldAdd adds a single firewalld rule
func (cr *CommandRunner) handleFirewalldAdd() (exitCode int, result string) {
	ruleData := map[string]interface{}{
		"zone":               cr.data.Zone,
		"protocol":           cr.data.Protocol,
		"port_start":         cr.data.PortStart,
		"port_end":           cr.data.PortEnd,
		"source":             cr.data.Source,
		"destination":        cr.data.Destination,
		"target":             cr.data.Target,
		"firewalld_rule_type": cr.data.FirewalldRuleType,
		"service":            cr.data.Service,
		"rule_id":            cr.data.RuleID,
	}

	if err := cr.executeFirewalldRule(ruleData); err != nil {
		return 1, fmt.Sprintf("Failed to add firewalld rule: %v", err)
	}

	return 0, fmt.Sprintf(`{"success": true, "rule_id": "%s"}`, cr.data.RuleID)
}

// handleFirewalldDelete deletes a firewalld rule
func (cr *CommandRunner) handleFirewalldDelete() (exitCode int, result string) {
	if cr.data.RuleID == "" {
		return 1, "firewalld delete: rule_id is required"
	}

	return cr.deleteFirewalldRule(cr.data.ChainName, cr.data.RuleID)
}

// handleFirewalldBatch applies multiple firewalld rules
func (cr *CommandRunner) handleFirewalldBatch() (exitCode int, result string) {
	if len(cr.data.Rules) == 0 {
		return 0, `{"success": true, "applied_rules": 0, "failed_rules": []}`
	}

	appliedCount := 0
	var failedRules []string

	for _, rule := range cr.data.Rules {
		if err := cr.executeFirewalldRule(rule); err != nil {
			log.Error().Err(err).Msg("Failed to apply firewalld rule")
			if ruleID, ok := rule["rule_id"].(string); ok {
				failedRules = append(failedRules, ruleID)
			}
		} else {
			appliedCount++
		}
	}

	if len(failedRules) > 0 {
		return 1, fmt.Sprintf(`{"success": false, "applied_rules": %d, "failed_rules": %d}`, appliedCount, len(failedRules))
	}

	return 0, fmt.Sprintf(`{"success": true, "applied_rules": %d, "failed_rules": []}`, appliedCount)
}

// handleFirewalldFlush flushes all rules in a firewalld zone
func (cr *CommandRunner) handleFirewalldFlush() (exitCode int, result string) {
	zone := cr.data.Zone
	if zone == "" {
		zone = "public"
	}

	// Remove all rich rules in the zone
	args := []string{"firewall-cmd", fmt.Sprintf("--zone=%s", zone), "--remove-rich-rules", "--permanent"}
	exitCode, output := runCmdWithOutput(args, "root", "", nil, 10)
	if exitCode != 0 {
		log.Warn().Msgf("Failed to remove rich rules from zone %s: %s", zone, output)
	}

	// Reload firewalld
	reloadArgs := []string{"firewall-cmd", "--reload"}
	exitCode, output = runCmdWithOutput(reloadArgs, "root", "", nil, 10)
	if exitCode != 0 {
		return 1, fmt.Sprintf("Failed to reload firewalld: %s", output)
	}

	return 0, fmt.Sprintf(`{"success": true, "flushed_zone": "%s"}`, zone)
}

// handleFirewalldUpdate updates a firewalld rule (delete old, add new)
func (cr *CommandRunner) handleFirewalldUpdate() (exitCode int, result string) {
	// Delete old rule
	if cr.data.OldRuleID != "" {
		_, _ = cr.deleteFirewalldRule(cr.data.ChainName, cr.data.OldRuleID)
	}

	// Add new rule
	return cr.handleFirewalldAdd()
}

// handleUFWAdd adds a single ufw rule
func (cr *CommandRunner) handleUFWAdd() (exitCode int, result string) {
	ruleData := map[string]interface{}{
		"protocol":    cr.data.Protocol,
		"port_start":  cr.data.PortStart,
		"port_end":    cr.data.PortEnd,
		"source":      cr.data.Source,
		"destination": cr.data.Destination,
		"target":      cr.data.Target,
		"direction":   cr.data.Direction,
		"interface":   cr.data.Interface,
		"rule_id":     cr.data.RuleID,
	}

	if err := cr.executeUFWRule(ruleData); err != nil {
		return 1, fmt.Sprintf("Failed to add ufw rule: %v", err)
	}

	return 0, fmt.Sprintf(`{"success": true, "rule_id": "%s"}`, cr.data.RuleID)
}

// handleUFWDelete deletes a ufw rule
func (cr *CommandRunner) handleUFWDelete() (exitCode int, result string) {
	if cr.data.RuleID == "" {
		return 1, "ufw delete: rule_id is required"
	}

	return cr.deleteUFWRule(cr.data.ChainName, cr.data.RuleID)
}

// handleUFWBatch applies multiple ufw rules
func (cr *CommandRunner) handleUFWBatch() (exitCode int, result string) {
	if len(cr.data.Rules) == 0 {
		return 0, `{"success": true, "applied_rules": 0, "failed_rules": []}`
	}

	appliedCount := 0
	var failedRules []string

	for _, rule := range cr.data.Rules {
		if err := cr.executeUFWRule(rule); err != nil {
			log.Error().Err(err).Msg("Failed to apply ufw rule")
			if ruleID, ok := rule["rule_id"].(string); ok {
				failedRules = append(failedRules, ruleID)
			}
		} else {
			appliedCount++
		}
	}

	if len(failedRules) > 0 {
		return 1, fmt.Sprintf(`{"success": false, "applied_rules": %d, "failed_rules": %d}`, appliedCount, len(failedRules))
	}

	return 0, fmt.Sprintf(`{"success": true, "applied_rules": %d, "failed_rules": []}`, appliedCount)
}

// handleUFWFlush resets ufw (removes all rules)
func (cr *CommandRunner) handleUFWFlush() (exitCode int, result string) {
	// Reset ufw to defaults
	args := []string{"ufw", "--force", "reset"}
	exitCode, output := runCmdWithOutput(args, "root", "", nil, 10)
	if exitCode != 0 {
		return 1, fmt.Sprintf("Failed to reset ufw: %s", output)
	}

	// Re-enable ufw
	enableArgs := []string{"ufw", "--force", "enable"}
	exitCode, output = runCmdWithOutput(enableArgs, "root", "", nil, 10)
	if exitCode != 0 {
		log.Warn().Msgf("Failed to re-enable ufw: %s", output)
	}

	return 0, `{"success": true, "message": "UFW reset to defaults"}`
}

// handleUFWUpdate updates a ufw rule (delete old, add new)
func (cr *CommandRunner) handleUFWUpdate() (exitCode int, result string) {
	// Delete old rule
	if cr.data.OldRuleID != "" {
		_, _ = cr.deleteUFWRule(cr.data.ChainName, cr.data.OldRuleID)
	}

	// Add new rule
	return cr.handleUFWAdd()
}

// executeFirewalldRule executes a firewall rule using firewalld
func (cr *CommandRunner) executeFirewalldRule(ruleData map[string]interface{}) error {
	// Extract rule data
	zone := cr.getStringField(ruleData, "zone", "public")
	protocol := cr.getStringField(ruleData, "protocol", "tcp")
	target := cr.getStringField(ruleData, "target", "ACCEPT")
	firewallRuleType := cr.getStringField(ruleData, "firewalld_rule_type", "port")

	// Determine if rule should be added or removed based on target
	action := "--add"
	if target == "DROP" || target == "REJECT" {
		action = "--remove"
	}

	var args []string

	switch firewallRuleType {
	case "service":
		// Service rule: firewall-cmd --zone=public --add-service=http
		service := cr.getStringField(ruleData, "service", "")
		if service == "" {
			return fmt.Errorf("service name is required for service rule type")
		}
		args = []string{
			"firewall-cmd",
			fmt.Sprintf("--zone=%s", zone),
			fmt.Sprintf("%s-service=%s", action, service),
		}

	case "port":
		// Port rule: firewall-cmd --zone=public --add-port=80/tcp
		portStart := cr.getIntField(ruleData, "port_start", 0)
		if portStart == 0 {
			return fmt.Errorf("port_start is required for port rule type")
		}

		portEnd := cr.getIntField(ruleData, "port_end", 0)
		var portSpec string
		if portEnd > 0 && portEnd != portStart {
			// Port range
			portSpec = fmt.Sprintf("%d-%d/%s", portStart, portEnd, protocol)
		} else {
			// Single port
			portSpec = fmt.Sprintf("%d/%s", portStart, protocol)
		}

		args = []string{
			"firewall-cmd",
			fmt.Sprintf("--zone=%s", zone),
			fmt.Sprintf("%s-port=%s", action, portSpec),
		}

	case "rich":
		// Rich rule: firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="80" protocol="tcp" accept'
		richRule := cr.buildFirewalldRichRule(ruleData)
		if richRule == "" {
			return fmt.Errorf("failed to build rich rule")
		}

		args = []string{
			"firewall-cmd",
			fmt.Sprintf("--zone=%s", zone),
			fmt.Sprintf("%s-rich-rule=%s", action, richRule),
		}

	default:
		return fmt.Errorf("unsupported firewalld rule type: %s", firewallRuleType)
	}

	// Add permanent flag
	args = append(args, "--permanent")

	// Execute the command
	exitCode, output := runCmdWithOutput(args, "root", "", nil, 10)
	if exitCode != 0 {
		return fmt.Errorf("firewall-cmd failed (exit %d): %s", exitCode, output)
	}

	// Reload firewalld to apply changes
	reloadArgs := []string{"firewall-cmd", "--reload"}
	exitCode, output = runCmdWithOutput(reloadArgs, "root", "", nil, 10)
	if exitCode != 0 {
		log.Warn().Msgf("Failed to reload firewalld: %s", output)
	}

	log.Debug().Msgf("Successfully executed firewalld rule in zone %s", zone)
	return nil
}

// buildFirewalldRichRule builds a firewalld rich rule from rule data
func (cr *CommandRunner) buildFirewalldRichRule(ruleData map[string]interface{}) string {
	var parts []string

	parts = append(parts, "rule family=\"ipv4\"")

	// Source
	source := cr.getStringField(ruleData, "source", "")
	if source != "" && source != "0.0.0.0/0" {
		parts = append(parts, fmt.Sprintf("source address=\"%s\"", source))
	}

	// Destination
	destination := cr.getStringField(ruleData, "destination", "")
	if destination != "" && destination != "0.0.0.0/0" {
		parts = append(parts, fmt.Sprintf("destination address=\"%s\"", destination))
	}

	// Port and protocol
	protocol := cr.getStringField(ruleData, "protocol", "tcp")
	portStart := cr.getIntField(ruleData, "port_start", 0)
	if portStart > 0 {
		portEnd := cr.getIntField(ruleData, "port_end", 0)
		if portEnd > 0 && portEnd != portStart {
			parts = append(parts, fmt.Sprintf("port port=\"%d-%d\" protocol=\"%s\"", portStart, portEnd, protocol))
		} else {
			parts = append(parts, fmt.Sprintf("port port=\"%d\" protocol=\"%s\"", portStart, protocol))
		}
	}

	// Target/action
	target := cr.getStringField(ruleData, "target", "ACCEPT")
	switch target {
	case "ACCEPT":
		parts = append(parts, "accept")
	case "DROP":
		parts = append(parts, "drop")
	case "REJECT":
		parts = append(parts, "reject")
	}

	return strings.Join(parts, " ")
}

// executeUFWRule executes a firewall rule using ufw
func (cr *CommandRunner) executeUFWRule(ruleData map[string]interface{}) error {
	// Extract rule data
	protocol := cr.getStringField(ruleData, "protocol", "tcp")
	target := cr.getStringField(ruleData, "target", "ACCEPT")
	direction := cr.getStringField(ruleData, "direction", "in")
	interfaceName := cr.getStringField(ruleData, "interface", "")

	// Determine action
	var action string
	switch target {
	case "ACCEPT":
		action = "allow"
	case "DROP":
		action = "deny"
	case "REJECT":
		action = "reject"
	default:
		action = "allow"
	}

	// Build ufw command
	args := []string{"ufw"}

	// Direction
	if direction == "out" {
		args = append(args, direction)
	}

	// Action
	args = append(args, action)

	// Interface
	if interfaceName != "" {
		args = append(args, "on", interfaceName)
	}

	// Port and protocol
	portStart := cr.getIntField(ruleData, "port_start", 0)
	if portStart > 0 {
		portEnd := cr.getIntField(ruleData, "port_end", 0)
		if portEnd > 0 && portEnd != portStart {
			// Port range
			args = append(args, fmt.Sprintf("%d:%d/%s", portStart, portEnd, protocol))
		} else {
			// Single port
			args = append(args, fmt.Sprintf("%d/%s", portStart, protocol))
		}
	} else {
		// No port specified, just protocol
		args = append(args, "proto", protocol)
	}

	// Source
	source := cr.getStringField(ruleData, "source", "")
	if source != "" && source != "0.0.0.0/0" {
		args = append(args, "from", source)
	}

	// Destination
	destination := cr.getStringField(ruleData, "destination", "")
	if destination != "" && destination != "0.0.0.0/0" {
		args = append(args, "to", destination)
	}

	// Add comment with rule ID
	ruleID := cr.getStringField(ruleData, "rule_id", "")
	if ruleID != "" {
		args = append(args, "comment", fmt.Sprintf("alpacon:%s", ruleID))
	}

	// Execute the command
	exitCode, output := runCmdWithOutput(args, "root", "", nil, 10)
	if exitCode != 0 {
		return fmt.Errorf("ufw failed (exit %d): %s", exitCode, output)
	}

	log.Debug().Msgf("Successfully executed ufw rule: %s", strings.Join(args, " "))
	return nil
}

// Helper functions to extract fields from rule data map
func (cr *CommandRunner) getStringField(data map[string]interface{}, key string, defaultValue string) string {
	if val, ok := data[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}

func (cr *CommandRunner) getIntField(data map[string]interface{}, key string, defaultValue int) int {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			// Try to parse string to int
			var intVal int
			fmt.Sscanf(v, "%d", &intVal)
			return intVal
		}
	}
	return defaultValue
}

// deleteFirewalldRule deletes a firewall rule from firewalld
func (cr *CommandRunner) deleteFirewalldRule(chainName string, ruleID string) (exitCode int, result string) {
	// For firewalld, we need to list rules and find the one with matching rule_id
	// This is more complex as firewalld doesn't have built-in rule ID tracking
	// For now, return error indicating this needs server-side tracking
	return 1, fmt.Sprintf("firewalld rule deletion by rule_id not yet implemented: %s", ruleID)
}

// deleteUFWRule deletes a firewall rule from ufw
func (cr *CommandRunner) deleteUFWRule(chainName string, ruleID string) (exitCode int, result string) {
	// List UFW rules with numbers
	listArgs := []string{"ufw", "status", "numbered"}
	exitCode, output := runCmdWithOutput(listArgs, "root", "", nil, 10)
	if exitCode != 0 {
		return 1, fmt.Sprintf("Failed to list ufw rules: %s", output)
	}

	// Find rule number by searching for rule_id in comment
	var ruleNumber int
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("alpacon:%s", ruleID)) {
			// Extract rule number from line like "[ 1] 22/tcp ALLOW Anywhere"
			fmt.Sscanf(line, "[ %d]", &ruleNumber)
			break
		}
	}

	if ruleNumber == 0 {
		return 1, fmt.Sprintf("UFW rule with ID %s not found", ruleID)
	}

	// Delete the rule by number
	deleteArgs := []string{"ufw", "delete", fmt.Sprintf("%d", ruleNumber)}
	exitCode, output = runCmdWithOutput(deleteArgs, "root", "", nil, 10)
	if exitCode != 0 {
		return 1, fmt.Sprintf("Failed to delete ufw rule: %s", output)
	}

	log.Info().Msgf("Deleted UFW rule #%d (rule_id: %s)", ruleNumber, ruleID)
	return 0, fmt.Sprintf(`{"success": true, "deleted_rule_id": "%s"}`, ruleID)
}
