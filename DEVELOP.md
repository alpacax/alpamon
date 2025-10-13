# Alpamon Firewall Development Guide

## Current Implementation Overview

### Core Components
1. **Firewall Sync** (`firewall_sync.go`): Collects and syncs firewall rules with UUID tracking
2. **Firewall Utils** (`firewall_utils.go`): Comment parsing and UUID management
3. **Command Handler** (`command.go`): Executes firewall operations (add/update/delete/batch)
4. **Commit Integration** (`commit.go`): Auto-syncs firewall rules during system commit

### Key Features
- ✅ UUID-based rule tracking via comments
- ✅ Efficient iptables-save/nftables JSON parsing
- ✅ Batch operations with mixed add/update/delete support
- ✅ Rollback capability on failure
- ✅ Installation caching to prevent apt-get lock conflicts

## Issues and Improvements

### 🔴 Critical Issues

1. **Missing Error Recovery in Update Operations**
   - **Location**: `handleUpdateOperation()` in `command.go`
   - **Issue**: No rollback mechanism if update fails mid-operation
   - **Fix**: Implement transaction-like behavior with original rule backup

2. **Race Condition in Firewall Installation**
   - **Location**: `installFirewall()` in `command.go`
   - **Issue**: Double-checked locking pattern not properly implemented
   - **Fix**: Move check inside mutex lock or use sync.Once properly

### 🟡 Medium Priority Improvements

1. **Incomplete Rule Type Support**
   - **Current**: Only supports tcp/udp/icmp/all
   - **Missing**: ESP, AH, SCTP, GRE protocols
   - **Location**: `parseIptablesRule()`, `parseNftablesRule()`

2. **Limited Chain Support**
   - **Current**: INPUT, OUTPUT, FORWARD only
   - **Issue**: No support for custom chains or NAT/MANGLE tables
   - **Location**: `collectFirewallRules()`

3. **Comment Size Limitation**
   - **Issue**: iptables comments limited to 256 chars, may truncate UUID data
   - **Location**: `buildFirewallComment()`
   - **Fix**: Implement comment compression or use alternate storage

4. **No IPv6 Support**
   - **Current**: Only IPv4 CIDR validation and parsing
   - **Missing**: ip6tables/nft inet family support
   - **Location**: Throughout firewall_sync.go

### 🟢 Enhancement Opportunities

1. **Performance Optimizations**
   ```go
   // Current: Sequential rule updates
   for _, rule := range rules {
       updateRule(rule)
   }

   // Better: Batch updates with prepared statements
   updateBatch(rules)
   ```

2. **Better Logging and Metrics**
   - Add structured logging with context
   - Implement metrics for sync performance
   - Track rule application success rates

3. **Configuration Management**
   ```go
   type FirewallConfig struct {
       MaxRetries      int
       SyncInterval    time.Duration
       BatchSize       int
       EnableIPv6      bool
       CustomChains    []string
   }
   ```

4. **Rule Validation Enhancement**
   - Validate port ranges (1-65535)
   - Check CIDR format strictly
   - Validate rule conflicts before applying

## Recommended Architecture Changes

### 1. Separate Concerns
```go
// Current: Everything in command.go
// Better: Separate into modules

firewall/
├── installer.go      // Installation logic
├── executor.go       // Rule execution
├── parser.go         // iptables/nftables parsing
├── validator.go      // Rule validation
└── rollback.go       // Rollback mechanisms
```

### 2. Interface-Based Design
```go
type FirewallManager interface {
    Install() error
    AddRule(rule Rule) error
    UpdateRule(id string, rule Rule) error
    DeleteRule(id string) error
    BatchApply(rules []Rule) error
    Rollback() error
}

type IptablesManager struct{}
type NftablesManager struct{}
```

### 3. Transaction Support
```go
type FirewallTransaction struct {
    rules    []Rule
    backup   []Rule
    applied  []string
}

func (t *FirewallTransaction) Begin() error
func (t *FirewallTransaction) Commit() error
func (t *FirewallTransaction) Rollback() error
```

## Testing Recommendations

1. **Unit Tests Needed**:
   - UUID generation and parsing
   - Comment building with edge cases
   - Rule parsing for all protocols
   - Batch operation with mixed operations

2. **Integration Tests**:
   - Full sync cycle with server
   - Rollback scenarios
   - Concurrent sync operations
   - Network failure handling

3. **Performance Tests**:
   - Large ruleset sync (1000+ rules)
   - Concurrent batch operations
   - Memory usage under load

## Security Considerations

1. **Command Injection**: Properly escape all shell arguments
2. **UUID Validation**: Ensure UUIDs are valid format
3. **Permission Checks**: Verify root access before operations
4. **Rate Limiting**: Prevent DoS via excessive sync requests

## Next Steps

1. **Immediate**: Fix race condition in firewall installation
2. **Short-term**: Add IPv6 support and custom chain handling
3. **Long-term**: Refactor to interface-based architecture
4. **Ongoing**: Improve test coverage to >80%