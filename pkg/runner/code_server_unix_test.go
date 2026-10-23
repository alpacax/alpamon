//go:build !windows

package runner

import (
	"os"
	"os/user"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrimaryGroupName_ReturnsTheUsersPrimaryGroup(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	want, err := user.LookupGroupId(current.Gid)
	require.NoError(t, err)

	got, err := primaryGroupName(current.Username)

	require.NoError(t, err)
	assert.Equal(t, want.Name, got)
}

func TestPrimaryGroupName_RejectsUnknownUser(t *testing.T) {
	_, err := primaryGroupName("alpamon-no-such-user")

	assert.ErrorContains(t, err, "there is no corresponding alpamon-no-such-user username")
}

// sudoInvokingUser is the account sudo was run from, standing in for the Alpacon session user.
func sudoInvokingUser(t *testing.T) *user.User {
	t.Helper()
	if runtime.GOOS != "darwin" || os.Getuid() != 0 {
		t.Skip("macOS root behavior")
	}
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		t.Skip("run under sudo from a regular account")
	}
	usr, err := user.Lookup(name)
	require.NoError(t, err)
	return usr
}

func TestEditorDarwinRootDemotesToPrimaryGroup(t *testing.T) {
	usr := sudoInvokingUser(t)
	primary, err := user.LookupGroupId(usr.Gid)
	require.NoError(t, err)

	id, err := lookupUserForCodeServer(usr.Username, "alpacon") // a Linux group the Mac does not have

	require.NoError(t, err)
	assert.Equal(t, primary.Name, id.groupname)
	assert.Equal(t, usr.HomeDir, id.homeDir)
	require.NotNil(t, id.procAttr, "a root Alpamon must not start code-server as root")
	gotUID := runWithCredential(t, id.procAttr.Credential, "id", "-u")
	gotGID := runWithCredential(t, id.procAttr.Credential, "id", "-g")
	assert.Equal(t, usr.Uid, gotUID)
	assert.Equal(t, usr.Gid, gotGID)
}
