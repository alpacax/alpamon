package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSupplementaryGroupsFrom pins that memberships are read by group name:
// two names sharing a gid must each answer for their own member list, so a
// reconcile never drops docker because devs has the same gid.
func TestSupplementaryGroupsFrom(t *testing.T) {
	group := strings.Join([]string{
		"# comment",
		"alice:x:1000:",
		"devs:x:2000:bob",
		"docker:x:2000:alice,bob",
		"adm:x:4:syslog, alice",
		"short:x:3000",
		"",
		"oldteam:x:3001:alice",
	}, "\n")

	got, err := SupplementaryGroupsFrom(strings.NewReader(group), "alice")

	require.NoError(t, err)
	assert.Equal(t, []string{"docker", "adm", "oldteam"}, got)
}
