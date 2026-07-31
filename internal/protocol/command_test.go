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
