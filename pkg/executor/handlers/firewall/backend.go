package firewall

import (
	"context"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// FirewallBackend defines the interface for firewall backend implementations
type FirewallBackend interface {
	// Name returns the backend name (e.g., "iptables", "nftables")
	Name() string

	// Detect checks if this firewall backend is available and active
	Detect(ctx context.Context) bool

	// AddRule adds a single firewall rule
	AddRule(ctx context.Context, rule *common.FirewallRule) error

	// DeleteRule removes a single firewall rule by ID
	DeleteRule(ctx context.Context, ruleID, chainName string) error

	// FlushChain removes all rules from a chain
	FlushChain(ctx context.Context, chainName string) error

	// DeleteChain deletes a chain entirely
	DeleteChain(ctx context.Context, chainName string) error

	// ListRules returns all rules in a chain
	ListRules(ctx context.Context, chainName string) ([]common.FirewallRule, error)

	// BatchApply applies multiple rules atomically
	// Returns: applied count, failed rule descriptions, error
	BatchApply(ctx context.Context, chainName string, rules []common.FirewallRule) (applied int, failed []string, err error)

	// ReorderChains reorders jump rules in INPUT chain
	ReorderChains(ctx context.Context, chainNames []string) (map[string]interface{}, error)

	// ReorderRules reorders rules within a chain
	ReorderRules(ctx context.Context, chainName string, rules []common.FirewallRule) error

	// Backup creates a backup of current firewall state
	Backup(ctx context.Context) (string, error)

	// Restore restores firewall state from backup
	Restore(ctx context.Context, backup string) error
}

// BatchResult represents the result of a batch operation
type BatchResult struct {
	Success      bool     `json:"success"`
	AppliedRules int      `json:"applied_rules"`
	FailedRules  []string `json:"failed_rules"`
	RolledBack   bool     `json:"rolled_back"`
	Message      string   `json:"message,omitempty"`
}

// ReorderResult represents the result of a reorder operation
type ReorderResult struct {
	Success        bool   `json:"success"`
	ReorderedCount int    `json:"reordered_count,omitempty"`
	DeletedRules   int    `json:"deleted_rules,omitempty"`
	Message        string `json:"message,omitempty"`
}
