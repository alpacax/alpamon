package protocol

import (
	"encoding/json"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// Command represents a command request from the server
type Command struct {
	ID    string            `json:"id"`
	Shell string            `json:"shell"`
	Line  string            `json:"line"`
	User  string            `json:"user"`
	Group string            `json:"group"`
	Env   map[string]string `json:"env"`
	Data  string            `json:"data,omitempty"`
}

// File represents a file in command data
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

// CommandData holds additional command parameters
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
	Operation               string                   `json:"operation"`
	RuleID                  string                   `json:"rule_id"`
	OldRuleID               string                   `json:"old_rule_id"`
	AssignmentID            string                   `json:"assignment_id"`
	ServerID                string                   `json:"server_id"`
	ChainNames              []string                 `json:"chain_names"`

	// Backend information
	Backend string `json:"backend"`
	Table   string `json:"table"`
	Family  string `json:"family"`

	// Firewalld specific fields
	Zone              string `json:"zone"`
	Service           string `json:"service"`
	FirewalldRuleType string `json:"firewalld_rule_type"`

	// UFW specific fields
	Direction string `json:"direction"`
	Interface string `json:"interface"`

	// Tunnel specific fields
	TargetPort int `json:"target_port"`
}

// ParseCommandData parses the Data field of a Command into CommandData
func (c *Command) ParseCommandData() (*CommandData, error) {
	if c.Data == "" {
		return &CommandData{}, nil
	}
	var data CommandData
	if err := json.Unmarshal([]byte(c.Data), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// ToArgs converts CommandData to CommandArgs for executor compatibility
func (c *CommandData) ToArgs() *common.CommandArgs {
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

		// Tunnel operations
		TargetPort: c.TargetPort,

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
			if v, ok := ruleMap["port_start"].(float64); ok {
				rule.PortStart = int(v)
			}
			if v, ok := ruleMap["port_end"].(float64); ok {
				rule.PortEnd = int(v)
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
			if v, ok := ruleMap["priority"].(float64); ok {
				rule.Priority = int(v)
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
