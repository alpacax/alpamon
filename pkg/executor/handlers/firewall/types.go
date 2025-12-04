package firewall

// FirewallData contains data for firewall operations
type FirewallData struct {
	Operation   string                   `json:"operation"`
	ChainName   string                   `json:"chain_name,omitempty"`
	Rules       []map[string]interface{} `json:"rules,omitempty"`
	RuleID      string                   `json:"rule_id,omitempty"`
	OldRuleID   string                   `json:"old_rule_id,omitempty"`
	ChainNames  []string                 `json:"chain_names,omitempty"`
	Method      string                   `json:"method,omitempty"`
	Chain       string                   `json:"chain,omitempty"`
	Protocol    string                   `json:"protocol,omitempty"`
	Source      string                   `json:"source,omitempty"`
	Destination string                   `json:"destination,omitempty"`
	Target      string                   `json:"target,omitempty"`
	Description string                   `json:"description,omitempty"`
}
