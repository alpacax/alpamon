package exposure

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Invalid report fixtures for the server: each is the default Ubuntu golden
// with exactly one defect the server must reject. They are derived here so
// they move with the golden.

func decodeTree(t *testing.T, body []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var tree map[string]any
	require.NoError(t, dec.Decode(&tree))
	return tree
}

// reseal recomputes the hash so the intended defect is the only one.
func reseal(t *testing.T, tree map[string]any) []byte {
	t.Helper()
	input := map[string]any{}
	for k, v := range tree {
		if k != "observed_at" && k != "hash" {
			input[k] = v
		}
	}
	canon, err := appendCanonical(nil, input)
	require.NoError(t, err)
	sum := sha256.Sum256(canon)
	if _, ok := tree["hash"]; ok {
		tree["hash"] = "sha256:" + hex.EncodeToString(sum[:])
	}
	out, err := appendCanonical(nil, tree)
	require.NoError(t, err)
	return out
}

func setCategory(tree map[string]any, name, status string, reasons ...string) {
	list := make([]any, 0, len(reasons))
	for _, r := range reasons {
		list = append(list, r)
	}
	tree["categories"].(map[string]any)[name] = map[string]any{"status": status, "reasons": list}
}

var invalidFixtures = map[string]func(tree map[string]any){
	"unknown-reason.json": func(tree map[string]any) {
		setCategory(tree, catKeys, coveragePartial, "file_rejected", "home_unreadable", "not_a_reason_code", "strict_modes_unresolved")
	},
	"server-only-reason.json": func(tree map[string]any) {
		setCategory(tree, catAccounts, coverageUnknown, "agent_unsupported")
	},
	"future-observed-at.json": func(tree map[string]any) {
		tree["observed_at"] = "2099-01-01T00:00:00Z"
	},
	"missing-required-field.json": func(tree map[string]any) {
		delete(tree, "categories")
	},
}

func TestInvalidFixtures(t *testing.T) {
	base, err := os.ReadFile(filepath.Join(fixturesDir, "hosts", "ubuntu-default", "expected.json"))
	require.NoError(t, err)
	for name, mutate := range invalidFixtures {
		t.Run(name, func(t *testing.T) {
			tree := decodeTree(t, base)
			mutate(tree)
			want := append(reseal(t, tree), '\n')
			p := filepath.Join(fixturesDir, "invalid", name)
			if updateGolden {
				require.NoError(t, os.WriteFile(p, want, 0o644))
			}
			got, err := os.ReadFile(p)
			require.NoError(t, err)
			assert.Equal(t, string(want), string(got), "regenerate with EXPOSURE_UPDATE_GOLDEN=1")
		})
	}

	// What makes each one invalid is something the agent never sends.
	unknown := decodeTree(t, mustRead(t, "invalid/unknown-reason.json"))
	assert.False(t, agentReasons["not_a_reason_code"])
	assert.NotNil(t, unknown["categories"])
	for _, r := range []string{"agent_unsupported", "no_report", "report_stale", "platform_unsupported"} {
		assert.False(t, agentReasons[r], "%s is server-only", r)
	}
	assert.NotContains(t, decodeTree(t, mustRead(t, "invalid/missing-required-field.json")), "categories")
}

func TestOversizeBody(t *testing.T) {
	body := oversizeBody(t)
	require.Greater(t, len(body), maxReportBytes)
	var report exposureReport
	require.NoError(t, json.Unmarshal(body, &report))
	body, err := finalize(&report)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(body), maxReportBytes)
}

func oversizeBody(t *testing.T) []byte {
	t.Helper()
	tree := decodeTree(t, mustRead(t, "hosts/ubuntu-default/expected.json"))
	accounts := tree["accounts"].([]any)
	template := accounts[len(accounts)-1]
	for i := 0; ; i++ {
		accounts = append(accounts, template)
		if i%256 == 0 {
			tree["accounts"] = accounts
			out, err := appendCanonical(nil, tree)
			require.NoError(t, err)
			if len(out) > maxReportBytes {
				return out
			}
		}
	}
}

func mustRead(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixturesDir, rel))
	require.NoError(t, err)
	return b
}
