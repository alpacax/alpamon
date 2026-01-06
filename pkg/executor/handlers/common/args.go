package common

import "time"

// CommandArgs is a strongly-typed struct for all command arguments
type CommandArgs struct {
	// Common fields
	SessionID string
	URL       string
	Command   string
	Timeout   time.Duration

	// User management
	Username                string
	Groupname               string
	Groupnames              []string
	HomeDirectory           string
	HomeDirectoryPermission string
	PurgeHomeDirectory      bool
	UID                     uint64
	GID                     uint64
	Comment                 string
	Shell                   string
	Groups                  []uint64

	// File operations
	Type           string
	Content        string
	Path           string
	Paths          []string
	Files          []File
	AllowOverwrite bool
	AllowUnzip     bool
	UseBlob        bool

	// Terminal operations
	Rows  uint16
	Cols  uint16
	Input string

	// Tunnel operations
	TargetPort int

	// Environment
	Env map[string]string

	// Firewall operations
	Keys         []string
	ChainName    string
	Method       string
	Chain        string
	Protocol     string
	PortStart    int
	PortEnd      int
	DPorts       []int
	ICMPType     string
	Source       string
	Destination  string
	Target       string
	Description  string
	Priority     int
	RuleType     string
	Rules        []FirewallRule
	Operation    string
	RuleID       string
	OldRuleID    string
	AssignmentID string
	ServerID     string
	ChainNames   []string

	// Backend information
	Backend string // Backend type: iptables, nftables, firewalld, ufw
	Table   string // iptables/nftables table: filter, nat, mangle, raw, security
	Family  string // IP family: ip (IPv4), ip6 (IPv6), inet, arp, bridge, netdev

	// Firewalld specific
	Zone              string // Firewalld zone (default, public, etc.)
	Service           string // Firewalld service name
	FirewalldRuleType string // Firewalld rule type: service, port, rich

	// UFW specific
	Direction string // UFW direction: in, out
	Interface string // UFW interface name
}

// File represents a file transfer operation
type File struct {
	Username       string `json:"username"`
	Groupname      string `json:"groupname"`
	Type           string `json:"type"`
	Content        string `json:"content"`
	Path           string `json:"path"`
	AllowOverwrite bool   `json:"allow_overwrite"`
	AllowUnzip     bool   `json:"allow_unzip"`
	URL            string `json:"url"`
}

// FirewallRule represents a single firewall rule
type FirewallRule struct {
	ChainName   string `json:"chain_name"`
	Method      string `json:"method"`
	Chain       string `json:"chain"`
	Protocol    string `json:"protocol"`
	PortStart   int    `json:"port_start"`
	PortEnd     int    `json:"port_end"`
	DPorts      []int  `json:"dports"`
	ICMPType    string `json:"icmp_type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	RuleType    string `json:"rule_type"`
	RuleID      string `json:"rule_id"`
	OldRuleID   string `json:"old_rule_id"`
	Operation   string `json:"operation"`
}
