package runner

import (
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/scheduler"
)

type Content struct {
	Query   string  `json:"query"`
	Command Command `json:"command,omitempty"`
	Reason  string  `json:"reason,omitempty"`
}

type Command struct {
	ID    string            `json:"id"`
	Shell string            `json:"shell"`
	Line  string            `json:"line"`
	User  string            `json:"user"`
	Group string            `json:"group"`
	Env   map[string]string `json:"env"`
	Data  string            `json:"data,omitempty"`
}

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

type CommandData struct {
	SessionID               string                   `json:"session_id"`
	URL                     string                   `json:"url"`
	Rows                    uint16                   `json:"rows"`
	Cols                    uint16                   `json:"cols"`
	Username                string                   `json:"username"`
	Groupname               string                   `json:"groupname"`
	Groupnames              []string                 `json:"groupnames"`
	HomeDirectory           string                   `json:"home_directory"`
	HomeDirectoryPermission string                   `json:"home_directory_permission"`
	PurgeHomeDirectory      bool                     `json:"purge_home"`
	UID                     uint64                   `json:"uid"`
	GID                     uint64                   `json:"gid"`
	Comment                 string                   `json:"comment"`
	Shell                   string                   `json:"shell"`
	Groups                  []uint64                 `json:"groups"`
	Type                    string                   `json:"type"`
	Content                 string                   `json:"content"`
	Path                    string                   `json:"path"`
	Paths                   []string                 `json:"paths"`
	Files                   []File                   `json:"files,omitempty"`
	AllowOverwrite          bool                     `json:"allow_overwrite,omitempty"`
	AllowUnzip              bool                     `json:"allow_unzip,omitempty"`
	UseBlob                 bool                     `json:"use_blob,omitempty"`
	Keys                    []string                 `json:"keys"`
	ChainName               string                   `json:"chain_name"`
	Method                  string                   `json:"method"`
	Chain                   string                   `json:"chain"`
	Protocol                string                   `json:"protocol"`
	PortStart               int                      `json:"port_start"`
	PortEnd                 int                      `json:"port_end"`
	DPorts                  []int                    `json:"dports"`
	ICMPType                string                   `json:"icmp_type"`
	Source                  string                   `json:"source"`
	Destination             string                   `json:"destination"`
	Target                  string                   `json:"target"`
	Description             string                   `json:"description"`
	Priority                int                      `json:"priority"`
	RuleType                string                   `json:"rule_type"`
	Rules                   []map[string]interface{} `json:"rules"`
	Operation               string                   `json:"operation"`   // batch, flush, delete, add, update
	RuleID                  string                   `json:"rule_id"`     // for rule-specific operations (add/update: new rule ID)
	OldRuleID               string                   `json:"old_rule_id"` // for update operation: old rule ID to delete
	AssignmentID            string                   `json:"assignment_id"`
	ServerID                string                   `json:"server_id"`
	ChainNames              []string                 `json:"chain_names"` // for firewall-reorder-chains

	// Backend information
	Backend string `json:"backend"` // Backend type: iptables, nftables, firewalld, ufw
	Table   string `json:"table"`   // iptables/nftables table: filter, nat, mangle, raw, security
	Family  string `json:"family"`  // IP family: ip (IPv4), ip6 (IPv6), inet, arp, bridge, netdev

	// Firewalld specific fields
	Zone              string `json:"zone"`                // Firewalld zone (default, public, etc.)
	Service           string `json:"service"`             // Firewalld service name
	FirewalldRuleType string `json:"firewalld_rule_type"` // Firewalld rule type: service, port, rich

	// UFW specific fields
	Direction string `json:"direction"` // UFW direction: in, out
	Interface string `json:"interface"` // UFW interface name
}

type CommandRunner struct {
	name       string
	command    Command
	wsClient   *WebsocketClient
	apiSession *scheduler.Session
	data       CommandData
	dispatcher CommandDispatcher // Interface for dispatcher to avoid circular dependency
}

type commandFin struct {
	Success     bool    `json:"success"`
	Result      string  `json:"result"`
	ElapsedTime float64 `json:"elapsed_time"`
}

// ToArgs converts CommandData to CommandArgs for type-safe executor compatibility
func (c CommandData) ToArgs() *common.CommandArgs {
	args := &common.CommandArgs{
		// Common fields
		SessionID: c.SessionID,
		URL:       c.URL,

		// User management
		Username:                c.Username,
		Groupname:               c.Groupname,
		Groupnames:              c.Groupnames,
		HomeDirectory:           c.HomeDirectory,
		HomeDirectoryPermission: c.HomeDirectoryPermission,
		PurgeHomeDirectory:      c.PurgeHomeDirectory,
		UID:                     c.UID,
		GID:                     c.GID,
		Comment:                 c.Comment,
		Shell:                   c.Shell,
		Groups:                  c.Groups,

		// File operations
		Type:           c.Type,
		Content:        c.Content,
		Path:           c.Path,
		Paths:          c.Paths,
		AllowOverwrite: c.AllowOverwrite,
		AllowUnzip:     c.AllowUnzip,
		UseBlob:        c.UseBlob,

		// Terminal operations
		Rows: c.Rows,
		Cols: c.Cols,

		// Firewall operations
		Keys:         c.Keys,
		ChainName:    c.ChainName,
		Method:       c.Method,
		Chain:        c.Chain,
		Protocol:     c.Protocol,
		PortStart:    c.PortStart,
		PortEnd:      c.PortEnd,
		DPorts:       c.DPorts,
		ICMPType:     c.ICMPType,
		Source:       c.Source,
		Destination:  c.Destination,
		Target:       c.Target,
		Description:  c.Description,
		Priority:     c.Priority,
		RuleType:     c.RuleType,
		Operation:    c.Operation,
		RuleID:       c.RuleID,
		OldRuleID:    c.OldRuleID,
		AssignmentID: c.AssignmentID,
		ServerID:     c.ServerID,
		ChainNames:   c.ChainNames,

		// Backend information
		Backend: c.Backend,
		Table:   c.Table,
		Family:  c.Family,

		// Firewalld specific
		Zone:              c.Zone,
		Service:           c.Service,
		FirewalldRuleType: c.FirewalldRuleType,

		// UFW specific
		Direction: c.Direction,
		Interface: c.Interface,
	}

	// Convert Files if present
	if len(c.Files) > 0 {
		args.Files = make([]common.File, len(c.Files))
		for i, f := range c.Files {
			args.Files[i] = common.File{
				Username:       f.Username,
				Groupname:      f.Groupname,
				Type:           f.Type,
				Content:        f.Content,
				Path:           f.Path,
				AllowOverwrite: f.AllowOverwrite,
				AllowUnzip:     f.AllowUnzip,
				URL:            f.URL,
			}
		}
	}

	// Convert Rules if present
	if len(c.Rules) > 0 {
		args.Rules = make([]common.FirewallRule, len(c.Rules))
		for i, ruleMap := range c.Rules {
			rule := common.FirewallRule{}
			if v, ok := ruleMap["chain_name"].(string); ok {
				rule.ChainName = v
			}
			if v, ok := ruleMap["method"].(string); ok {
				rule.Method = v
			}
			if v, ok := ruleMap["chain"].(string); ok {
				rule.Chain = v
			}
			if v, ok := ruleMap["protocol"].(string); ok {
				rule.Protocol = v
			}
			if v, ok := ruleMap["port_start"].(int); ok {
				rule.PortStart = v
			}
			if v, ok := ruleMap["port_end"].(int); ok {
				rule.PortEnd = v
			}
			if v, ok := ruleMap["dports"].([]int); ok {
				rule.DPorts = v
			}
			if v, ok := ruleMap["icmp_type"].(string); ok {
				rule.ICMPType = v
			}
			if v, ok := ruleMap["source"].(string); ok {
				rule.Source = v
			}
			if v, ok := ruleMap["destination"].(string); ok {
				rule.Destination = v
			}
			if v, ok := ruleMap["target"].(string); ok {
				rule.Target = v
			}
			if v, ok := ruleMap["description"].(string); ok {
				rule.Description = v
			}
			if v, ok := ruleMap["priority"].(int); ok {
				rule.Priority = v
			}
			if v, ok := ruleMap["rule_type"].(string); ok {
				rule.RuleType = v
			}
			if v, ok := ruleMap["rule_id"].(string); ok {
				rule.RuleID = v
			}
			if v, ok := ruleMap["old_rule_id"].(string); ok {
				rule.OldRuleID = v
			}
			if v, ok := ruleMap["operation"].(string); ok {
				rule.Operation = v
			}
			args.Rules[i] = rule
		}
	}

	return args
}

var nonZipExt = map[string]bool{
	".jar":   true,
	".war":   true,
	".ear":   true,
	".apk":   true,
	".xpi":   true,
	".vsix":  true,
	".crx":   true,
	".egg":   true,
	".whl":   true,
	".appx":  true,
	".msix":  true,
	".ipk":   true,
	".nupkg": true,
	".kmz":   true,
}
