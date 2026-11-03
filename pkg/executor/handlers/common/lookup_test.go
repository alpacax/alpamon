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

	got, err := supplementaryGroupsFrom(strings.NewReader(group), "alice")

	require.NoError(t, err)
	assert.Equal(t, []string{"docker", "adm", "oldteam"}, got)
}

// TestSupplementaryGroupsFrom_Edges pins the os/user parser's parity: NIS
// compat and nameless entries never become group names, and a member list
// longer than bufio.Scanner's 64 KiB default still parses.
func TestSupplementaryGroupsFrom_Edges(t *testing.T) {
	many := strings.Repeat("someone,", 10000) + "alice"
	group := strings.Join([]string{
		"+nis:::alice",
		"-blocked:::alice",
		":x:9:alice",
		"big:x:5000:" + many,
		"last:x:5001:alice",
	}, "\n")

	got, err := supplementaryGroupsFrom(strings.NewReader(group), "alice")

	require.NoError(t, err)
	assert.Equal(t, []string{"big", "last"}, got)
}
