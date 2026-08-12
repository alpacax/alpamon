package protocol

import (
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCommandData_PackageProxy verifies that the optional package_proxy
// field in the upgrade command payload is parsed and mapped into CommandArgs.
func TestParseCommandData_PackageProxy(t *testing.T) {
	cmd := &Command{
		ID:    "test-123",
		Shell: "internal",
		Line:  "upgrade",
		Data:  `{"package_proxy": "http://proxy.internal:3128"}`,
	}

	data, err := cmd.ParseCommandData()
	require.NoError(t, err)
	assert.Equal(t, "http://proxy.internal:3128", data.PackageProxy)

	args := data.ToArgs()
	assert.Equal(t, "http://proxy.internal:3128", args.PackageProxy)
}

// TestParseCommandData_PackageProxyAbsent pins backward compatibility: older
// servers omit package_proxy (or send no data at all) and the field must
// resolve to empty without error.
func TestParseCommandData_PackageProxyAbsent(t *testing.T) {
	for name, data := range map[string]string{
		"empty data":  "",
		"other field": `{"session_id": "sess-456"}`,
	} {
		t.Run(name, func(t *testing.T) {
			cmd := &Command{Shell: "internal", Line: "upgrade", Data: data}

			parsed, err := cmd.ParseCommandData()
			require.NoError(t, err)
			assert.Empty(t, parsed.PackageProxy)
			assert.Empty(t, parsed.ToArgs().PackageProxy)
		})
	}
}

// TestParseCommandData_BatchRuleFields pins the batch rule conversion, which is
// the only place a firewall rule field is converted: the handler reads nothing
// off CommandArgs but ChainName, ChainNames, OldRuleID, Operation, RuleID and
// Rules. Every field is asserted at once so a future drop fails here whichever
// field it is. dports matters most: dropping it installs a rule with no port
// match at all, which opens every port on the protocol instead of the two the
// console shows.
func TestParseCommandData_BatchRuleFields(t *testing.T) {
	cmd := &Command{
		ID:    "fw-batch-1",
		Shell: "internal",
		Line:  "batch",
		Data: `{"chain_name": "ALPACON_INPUT", "operation": "batch", "rules": [
			{
				"chain_name": "ALPACON_INPUT", "method": "insert", "chain": "INPUT",
				"protocol": "tcp", "port_start": 8000, "port_end": 8010,
				"dports": [80, 443], "icmp_type": "echo-request",
				"source": "10.0.0.0/8", "destination": "192.168.0.1",
				"target": "ACCEPT", "description": "web", "priority": 10,
				"rule_type": "alpacon", "rule_id": "rule-1", "old_rule_id": "rule-0",
				"operation": "add"
			},
			{"chain": "INPUT", "protocol": "tcp", "port_start": 8000, "port_end": 8010, "target": "ACCEPT"}
		]}`,
	}

	data, err := cmd.ParseCommandData()
	require.NoError(t, err)

	args := data.ToArgs()
	require.Len(t, args.Rules, 2)

	assert.Equal(t, common.FirewallRule{
		ChainName:   "ALPACON_INPUT",
		Method:      "insert",
		Chain:       "INPUT",
		Protocol:    "tcp",
		PortStart:   8000,
		PortEnd:     8010,
		DPorts:      []int{80, 443},
		ICMPType:    "echo-request",
		Source:      "10.0.0.0/8",
		Destination: "192.168.0.1",
		Target:      "ACCEPT",
		Description: "web",
		Priority:    10,
		RuleType:    "alpacon",
		RuleID:      "rule-1",
		OldRuleID:   "rule-0",
		Operation:   "add",
	}, args.Rules[0])

	// A dports rule must not contaminate a neighbouring range rule.
	assert.Empty(t, args.Rules[1].DPorts)
	assert.Equal(t, 8000, args.Rules[1].PortStart)
	assert.Equal(t, 8010, args.Rules[1].PortEnd)
}

// TestParseCommandData_BatchRuleDPortsAsStrings covers senders that emit dports
// as strings rather than numbers, which the snapshot-restore payload does.
func TestParseCommandData_BatchRuleDPortsAsStrings(t *testing.T) {
	cmd := &Command{
		ID:    "fw-batch-2",
		Shell: "internal",
		Line:  "batch",
		Data: `{"chain_name": "ALPACON_INPUT", "operation": "batch", "rules": [
			{"chain": "INPUT", "protocol": "tcp", "dports": ["80", "443"], "target": "ACCEPT"},
			{"chain": "INPUT", "protocol": "tcp", "dports": ["80", "not-a-port"], "target": "ACCEPT"}
		]}`,
	}

	data, err := cmd.ParseCommandData()
	require.NoError(t, err)

	args := data.ToArgs()
	require.Len(t, args.Rules, 2)

	assert.Equal(t, []int{80, 443}, args.Rules[0].DPorts)
	assert.Equal(t, []int{80}, args.Rules[1].DPorts)
}
