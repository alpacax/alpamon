# Firewall Commands Specification

This document describes the firewall-related internal commands that Alpamon agent handles.

## Overview

Alpamon manages firewall rules using iptables. All operations are designed to be atomic - either all rules are applied successfully, or the system is rolled back to its previous state.

## Commands

### 1. firewall-batch-apply

Applies firewall rules incrementally to a security group (adds new rules without removing existing ones). This is an atomic operation that will automatically rollback on any failure.

**Request Data Structure:**
```json
{
    "action": "apply_security_group",
    "assignment_id": "uuid-of-assignment",
    "security_group_name": "sg-name",
    "rules": [
        {
            "chain_name": "security-group-name",
            "method": "-A",  // or "-I" for insert
            "chain": "INPUT",
            "protocol": "tcp",  // tcp/udp/icmp/all
            "port_start": 80,
            "port_end": 80,
            "dports": [80, 443],  // destination ports for multiport
            "sports": [1024],     // source ports for multiport (optional)
            "icmp_type": null,    // for ICMP protocol
            "source": "0.0.0.0/0",      // source CIDR
            "destination": "192.168.1.0/24",  // destination CIDR (optional)
            "interface": "eth0",  // input interface (optional)
            "out_interface": "eth1",  // output interface (optional)  
            "state": "NEW,ESTABLISHED",  // connection state (optional)
            "target": "ACCEPT",   // ACCEPT/DROP/REJECT
            "description": "Allow HTTP",
            "priority": 100,
            "rule_type": "user",  // user/server (optional, defaults to "user")
            "rule_handle": "5"    // for direct deletion by handle (optional)
        }
    ]
}
```

**Response Structure:**
```json
{
    "success": true,
    "applied_rules": 5,  // number of successfully applied rules
    "failed_rules": [],  // list of failed rules with errors
    "rolled_back": false,  // true if rollback was performed
    "rollback_reason": null  // reason for rollback if performed
}
```

**Error Response:**
```json
{
    "success": false,
    "error": "Failed to apply rules: iptables error",
    "applied_rules": 2,
    "failed_rules": [
        {
            "rule": "rule description or index",
            "error": "specific error message"
        }
    ],
    "rolled_back": true,
    "rollback_reason": "Rule 3 failed to apply"
}
```

### 2. firewall-rules

Manages individual firewall rules or applies a complete rule set. Supports add, update, delete, and apply operations.

**Request Data Structure:**

**Add Rule:**
```json
{
    "action": "add_rule",
    "chain_name": "security-group-name",
    "rule": {
        // same structure as rules in batch-apply
    },
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Update Rule:**
```json
{
    "action": "update_rule",
    "chain_name": "security-group-name",
    "rule": {
        // updated rule data
    },
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Delete Rule:**
```json
{
    "action": "delete_rule",
    "chain_name": "security-group-name",
    "rule": {
        // rule identification data
    },
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Apply All Rules (Replace):**
```json
{
    "action": "apply_rules",
    "chain_name": "security-group-name",
    "rules": [
        // array of rules - will replace ALL existing rules
    ],
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Note:** 
- `apply_rules` will flush all existing rules and apply the provided rules (full replacement)
- Use `firewall-batch-apply` for incremental rule addition without removing existing rules

**Response Structure:**
```json
{
    "success": true,
    "message": "Rule added successfully"
}
```

### 3. firewall-rollback

Rolls back firewall rules to a previous state, flushes all rules, or completely deletes a security group.

**Request Data Structure:**

**Restore from Snapshot:**
```json
{
    "action": "restore",
    "chain_name": "security-group-name",
    "rules": [
        // array of rules to restore
    ],
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Flush Chain (Remove rules only):**
```json
{
    "action": "flush",
    "chain_name": "security-group-name",
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Delete Chain/Table (Complete removal):**
```json
{
    "action": "delete",
    "chain_name": "security-group-name",
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Response Structure:**
```json
{
    "success": true,
    "message": "Rollback completed successfully"
}
```

### 4. firewall-chain-delete

Deletes a specific firewall chain or all chains in a security group. This operation first flushes all rules then completely removes the chain structure. This operation is immediate and does not provide automatic rollback.

**Request Data Structure:**

**Delete Specific Chain:**
```json
{
    "chain_name": "security-group-name",
    "chain": "INPUT",  // optional: specific chain type (INPUT/OUTPUT/FORWARD)
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Delete All Chains (Security Group):**
```json
{
    "chain_name": "security-group-name",
    "assignment_id": "uuid",
    "server_id": "uuid"
}
```

**Response Structure:**
```json
{
    "success": true,
    "message": "Successfully deleted chain security-group-name.input"
}
```

**Multi-chain Response:**
```json
{
    "success": true,
    "message": "Successfully deleted 3 chains for security group security-group-name"
}
```

**Error Response:**
```json
{
    "success": false,
    "message": "iptables chain delete error: No chain/target/match by that name"
}
```

**Operation Details:**
- **nftables**: Uses `nft delete chain ip <table> <chain>` for specific chains or `nft delete table ip <table>` for entire table
- **iptables**: Uses `iptables -F <chainname> && iptables -X <chainname>` for each chain type (input, output, forward)
- Non-existent chains are considered successfully deleted (idempotent operation)
- Automatically flushes chains before deletion to avoid conflicts
- No automatic rollback - deleted chains must be recreated manually

## Rule Type Classification

The `rule_type` field categorizes firewall rules based on their origin:

- **user**: Rules created through Alpacon server API by users (default)
- **server**: Rules automatically generated by system processes

Rules are stored with metadata in firewall comments for tracking and management purposes.

## Rule Examples

### Basic HTTP/HTTPS Rule
```json
{
    "chain": "INPUT",
    "protocol": "tcp",
    "dports": [80, 443],
    "source": "0.0.0.0/0",
    "target": "ACCEPT"
}
```

### SSH from Specific Network
```json
{
    "chain": "INPUT", 
    "protocol": "tcp",
    "port_start": 22,
    "source": "192.168.1.0/24",
    "target": "ACCEPT"
}
```

### Interface-Specific Rule
```json
{
    "chain": "FORWARD",
    "interface": "eth0",
    "out_interface": "eth1", 
    "protocol": "tcp",
    "target": "ACCEPT"
}
```

### Stateful Connection Rule
```json
{
    "chain": "INPUT",
    "protocol": "tcp",
    "state": "ESTABLISHED,RELATED",
    "target": "ACCEPT"
}
```

### Rule Deletion by Handle
```json
{
    "action": "delete_rule",
    "chain_name": "sg-web",
    "chain": "INPUT", 
    "rule_handle": "5"
}
```

### Rule Deletion by Content (Partial Match)
```json
{
    "action": "delete_rule",
    "chain_name": "sg-web",
    "chain": "INPUT",
    "protocol": "tcp",
    "port_start": 80,
    "target": "ACCEPT"
}
```

## Implementation Notes

### Atomic Operations

1. **Pre-operation Backup**: Before applying any changes, save current iptables state
2. **Rule Application**: Apply rules one by one, tracking success/failure
3. **Automatic Rollback**: On any failure, restore from pre-operation backup
4. **Status Reporting**: Report detailed status including which rules succeeded/failed

### Chain Management

- Each security group maps to a custom iptables chain or nftables table
- Chain names should be prefixed to avoid conflicts (e.g., `alpacon-{sg-name}`)
- Chains are referenced from the main INPUT/OUTPUT chains

**Operation Types:**
- **flush**: Removes all rules but preserves chain/table structure (for rule updates)
- **delete**: Completely removes chain/table structure (for security group unassign)
  - nftables: `nft delete table ip {chain_name}`
  - iptables: `iptables -F {chain_name}_* && iptables -X {chain_name}_*`

### Error Handling

1. **Validation Errors**: Check rule syntax before applying
2. **iptables Errors**: Capture and parse iptables error messages
3. **System Errors**: Handle permission issues, missing commands, etc.
4. **Rollback Errors**: If rollback fails, log critical error and alert

### Performance Considerations

- Use iptables-restore for batch operations when possible
- Minimize individual iptables calls
- Cache current state to reduce system calls
- Use ipset for large IP lists

### Security Considerations

- Validate all input parameters
- Ensure rules don't lock out management access
- Log all firewall changes for audit
- Implement rate limiting for rule changes