package runner

import (
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeServerIDs(t *testing.T) {
	// Regression guard: utils.Demote would skip demotion here and run as root.
	t.Run("empty groupname falls back to the primary group", func(t *testing.T) {
		uid, gid, err := codeServerIDs(&user.User{Uid: "1000", Gid: "1000"}, "")
		require.NoError(t, err)
		assert.Equal(t, uint32(1000), uid)
		assert.Equal(t, uint32(1000), gid)
	})

	t.Run("groupname overrides the primary group", func(t *testing.T) {
		// Skip rather than fail: an unreadable group database is an environment
		// problem, not a codeServerIDs defect.
		grp, err := user.LookupGroupId("0")
		if err != nil {
			t.Skipf("gid 0 is not resolvable on this host: %v", err)
		}

		uid, gid, err := codeServerIDs(&user.User{Uid: "1000", Gid: "1000"}, grp.Name)
		require.NoError(t, err)
		assert.Equal(t, uint32(1000), uid)
		assert.Equal(t, uint32(0), gid)
	})

	t.Run("unknown groupname is an error", func(t *testing.T) {
		_, _, err := codeServerIDs(&user.User{Uid: "1000", Gid: "1000"}, "alpamon-nonexistent-group")
		assert.Error(t, err)
	})

	t.Run("unparsable uid is an error", func(t *testing.T) {
		_, _, err := codeServerIDs(&user.User{Uid: "not-a-uid", Gid: "1000"}, "")
		assert.Error(t, err)
	})
}
