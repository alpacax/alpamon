package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// Validator validates firewall rules before execution
type Validator struct{}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateRule validates a single firewall rule
func (v *Validator) ValidateRule(rule *common.FirewallRule) error {
	// Validate chain name if provided
	if rule.Chain != "" {
		if err := v.ValidateChainName(rule.Chain); err != nil {
			return err
		}
	}

	// Validate protocol
	if rule.Protocol != "" {
		if err := v.ValidateProtocol(rule.Protocol); err != nil {
			return err
		}
	}

	// Validate port start
	if rule.PortStart != 0 {
		if err := v.ValidatePort(rule.PortStart); err != nil {
			return fmt.Errorf("invalid port_start: %w", err)
		}
	}

	// Validate port end
	if rule.PortEnd != 0 {
		if err := v.ValidatePort(rule.PortEnd); err != nil {
			return fmt.Errorf("invalid port_end: %w", err)
		}
	}

	// Validate port range if both start and end provided
	if rule.PortStart != 0 && rule.PortEnd != 0 {
		if err := v.ValidatePortRange(rule.PortStart, rule.PortEnd); err != nil {
			return err
		}
	}

	// Validate DPorts
	for i, port := range rule.DPorts {
		if err := v.ValidatePort(port); err != nil {
			return fmt.Errorf("invalid dports[%d]: %w", i, err)
		}
	}

	// Validate source CIDR
	if rule.Source != "" && rule.Source != "0.0.0.0/0" {
		if err := v.ValidateCIDR(rule.Source); err != nil {
			return fmt.Errorf("invalid source: %w", err)
		}
	}

	// Validate destination CIDR
	if rule.Destination != "" && rule.Destination != "0.0.0.0/0" {
		if err := v.ValidateCIDR(rule.Destination); err != nil {
			return fmt.Errorf("invalid destination: %w", err)
		}
	}

	// Validate target
	if rule.Target != "" {
		if err := v.ValidateTarget(rule.Target); err != nil {
			return err
		}
	}

	// Validate ICMP type if protocol is ICMP
	if rule.Protocol == "icmp" && rule.ICMPType != "" {
		if err := v.ValidateICMPType(rule.ICMPType); err != nil {
			return err
		}
	}

	return nil
}

// ValidateChainName validates a chain name
func (v *Validator) ValidateChainName(chainName string) error {
	if chainName == "" {
		return fmt.Errorf("chain name cannot be empty")
	}

	// Check for valid characters (alphanumeric, underscore, hyphen)
	for _, c := range chainName {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-') {
			return fmt.Errorf("invalid character '%c' in chain name", c)
		}
	}

	// Maximum length check (iptables limit is 29 characters)
	if len(chainName) > 29 {
		return fmt.Errorf("chain name too long (max 29 characters)")
	}

	return nil
}

// ValidateProtocol validates the protocol field
func (v *Validator) ValidateProtocol(protocol string) error {
	validProtocols := map[string]bool{
		"tcp":  true,
		"udp":  true,
		"icmp": true,
		"all":  true,
		"":     true, // empty is valid (defaults to all)
	}

	if !validProtocols[strings.ToLower(protocol)] {
		return fmt.Errorf("invalid protocol '%s' (allowed: tcp, udp, icmp, all)", protocol)
	}

	return nil
}

// ValidatePort validates a port number
func (v *Validator) ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}
	return nil
}

// ValidatePortRange validates a port range
func (v *Validator) ValidatePortRange(start, end int) error {
	if start > end {
		return fmt.Errorf("port range invalid: start (%d) > end (%d)", start, end)
	}
	return nil
}

// ValidateCIDR validates an IP address or CIDR notation
func (v *Validator) ValidateCIDR(cidr string) error {
	// Try parsing as CIDR first
	_, _, err := net.ParseCIDR(cidr)
	if err == nil {
		return nil
	}

	// Try parsing as plain IP address
	ip := net.ParseIP(cidr)
	if ip != nil {
		return nil
	}

	return fmt.Errorf("invalid IP address or CIDR notation: %s", cidr)
}

// ValidateTarget validates a firewall target/action
func (v *Validator) ValidateTarget(target string) error {
	validTargets := map[string]bool{
		"ACCEPT": true,
		"DROP":   true,
		"REJECT": true,
		"LOG":    true,
		"RETURN": true,
		"accept": true,
		"drop":   true,
		"reject": true,
		"log":    true,
		"return": true,
	}

	if !validTargets[target] {
		return fmt.Errorf("invalid target '%s' (allowed: ACCEPT, DROP, REJECT, LOG, RETURN)", target)
	}

	return nil
}

// ValidateICMPType validates an ICMP type
func (v *Validator) ValidateICMPType(icmpType string) error {
	// Common ICMP types (names or numbers)
	validTypes := map[string]bool{
		"echo-reply":              true,
		"destination-unreachable": true,
		"redirect":                true,
		"echo-request":            true,
		"time-exceeded":           true,
		"parameter-problem":       true,
		"timestamp-request":       true,
		"timestamp-reply":         true,
		"address-mask-request":    true,
		"address-mask-reply":      true,
	}

	// Check if it's a valid name
	if validTypes[strings.ToLower(icmpType)] {
		return nil
	}

	// Check if it's a valid number (0-255)
	num, err := strconv.Atoi(icmpType)
	if err == nil && num >= 0 && num <= 255 {
		return nil
	}

	return fmt.Errorf("invalid ICMP type '%s'", icmpType)
}

// ValidateBatchRules validates a batch of rules
func (v *Validator) ValidateBatchRules(rules []common.FirewallRule) error {
	for i, rule := range rules {
		if err := v.ValidateRule(&rule); err != nil {
			return fmt.Errorf("rule[%d]: %w", i, err)
		}
	}
	return nil
}
