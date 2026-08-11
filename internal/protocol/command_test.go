package protocol

import (
	"testing"

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

// TestParseCommandData_BatchRuleDPorts pins the batch rule conversion: a rule
// carrying dports must reach CommandArgs with its ports intact. Dropping them
// installs a rule with no port match at all, which opens every port on the
// protocol instead of the two the console shows.
func TestParseCommandData_BatchRuleDPorts(t *testing.T) {
	cmd := &Command{
		ID:    "fw-batch-1",
		Shell: "internal",
		Line:  "batch",
		Data: `{"chain_name": "ALPACON_INPUT", "operation": "batch", "rules": [
			{"chain": "INPUT", "protocol": "tcp", "dports": [80, 443], "target": "ACCEPT"},
			{"chain": "INPUT", "protocol": "tcp", "port_start": 8000, "port_end": 8010, "target": "ACCEPT"}
		]}`,
	}

	data, err := cmd.ParseCommandData()
	require.NoError(t, err)

	args := data.ToArgs()
	require.Len(t, args.Rules, 2)

	assert.Equal(t, []int{80, 443}, args.Rules[0].DPorts)
	assert.Zero(t, args.Rules[0].PortStart)

	assert.Empty(t, args.Rules[1].DPorts)
	assert.Equal(t, 8000, args.Rules[1].PortStart)
	assert.Equal(t, 8010, args.Rules[1].PortEnd)
}
