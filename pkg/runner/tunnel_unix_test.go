//go:build !windows

package runner

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupNobodyIDs resolves nobody independently of the code under test, skipping
// where the image ships no nobody account (opensuse/leap:15).
func lookupNobodyIDs(t *testing.T) (uint32, uint32) {
	t.Helper()
	usr, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account on this system: %v", err)
	}
	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	require.NoError(t, err)
	gid, err := strconv.ParseUint(usr.Gid, 10, 32)
	require.NoError(t, err)
	return uint32(uid), uint32(gid)
}

func TestTunnelDaemonCredential_RootDemotesToNobodyWithoutSupplementaryGroups(t *testing.T) {
	wantUID, wantGID := lookupNobodyIDs(t)

	cred, err := tunnelDaemonCredential(true)

	require.NoError(t, err)
	require.NotNil(t, cred, "a root Alpamon must not start the tunnel daemon as root")
	assert.Equal(t, wantUID, cred.Uid)
	assert.Equal(t, wantGID, cred.Gid)
	assert.Nil(t, cred.Groups)
}

func TestTunnelDaemonCredential_RootFailsWithoutNobody(t *testing.T) {
	if _, err := user.Lookup("nobody"); err == nil {
		t.Skip("this system has a nobody account")
	}

	cred, err := tunnelDaemonCredential(true)

	assert.ErrorContains(t, err, "failed to lookup nobody user")
	assert.Nil(t, cred)
}

func TestTunnelDaemonCredential_NonRootKeepsCurrentUser(t *testing.T) {
	cred, err := tunnelDaemonCredential(false)

	require.NoError(t, err)
	assert.Nil(t, cred)
}

func TestParseUserCredentials(t *testing.T) {
	cases := []struct {
		name    string
		uid     string
		gid     string
		wantUID uint32
		wantGID uint32
		wantErr string
	}{
		{"Linux nobody", "65534", "65534", 65534, 65534, ""},
		{"macOS nobody past MaxInt32", "4294967294", "4294967294", 4294967294, 4294967294, ""},
		{"empty uid", "", "", 0, 0, "invalid uid"},
		{"negative uid", "-2", "0", 0, 0, "invalid uid"},
		{"uid past uint32 must not wrap to root", "4294967296", "0", 0, 0, "invalid uid"},
		{"non-numeric gid", "0", "abc", 0, 0, "invalid gid"},
		{"negative gid", "0", "-2", 0, 0, "invalid gid"},
		{"gid past uint32 must not wrap to root", "0", "4294967296", 0, 0, "invalid gid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid, err := parseUserCredentials(tc.uid, tc.gid)

			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantUID, uid)
			assert.Equal(t, tc.wantGID, gid)
		})
	}
}

func TestTunnelDaemonCredential_RootChildRunsAsNobodyWithoutSupplementaryGroups(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to switch the child's uid")
	}
	wantUID, wantGID := lookupNobodyIDs(t)
	cred, err := tunnelDaemonCredential(true)
	require.NoError(t, err)

	gotUID := runWithCredential(t, cred, "id", "-u")
	gotGID := runWithCredential(t, cred, "id", "-g")

	assert.Equal(t, strconv.FormatUint(uint64(wantUID), 10), gotUID)
	assert.Equal(t, strconv.FormatUint(uint64(wantGID), 10), gotGID)
	if runtime.GOOS == "linux" { // macOS id -G mixes in directory-service memberships, so only the kernel view is checked
		assert.Equal(t, "Groups:", runWithCredential(t, cred, "grep", "^Groups:", "/proc/self/status"))
	}
}

func TestTunnelDaemonCommand_CarriesTheDaemonCredential(t *testing.T) {
	cases := []struct {
		name   string
		daemon *syscall.Credential
	}{
		{"root demotes to the daemon credential", &syscall.Credential{Uid: 65534, Gid: 65534}},
		{"non-root keeps the current user", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tunnelDaemonCommand("/usr/local/bin/alpamon", "/tmp/alpamon-tunnels/t.sock", tc.daemon)

			assert.Equal(t, []string{"/usr/local/bin/alpamon", "tunnel-daemon", "/tmp/alpamon-tunnels/t.sock"}, cmd.Args)
			require.NotNil(t, cmd.SysProcAttr)
			assert.Same(t, tc.daemon, cmd.SysProcAttr.Credential)
			assert.True(t, cmd.SysProcAttr.Setpgid)
		})
	}
}
