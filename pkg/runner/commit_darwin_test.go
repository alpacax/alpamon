package runner

import (
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDsclUsers_SeparatesRecords(t *testing.T) {
	// Given
	out := `NFSHomeDirectory: /var/root
PrimaryGroupID: 0
RecordName: root
UniqueID: 0
UserShell: /bin/sh
-
NFSHomeDirectory: /Users/alice
PrimaryGroupID: 20
RecordName: alice
UniqueID: 501
UserShell: /bin/zsh
`
	shells := []string{"/bin/zsh"}

	// When
	users := parseDsclUsers(out, shells)

	// Then
	require.Len(t, users, 2)
	assert.Equal(t, UserData{Username: "root", UID: 0, GID: 0, Directory: "/var/root", Shell: "/bin/sh", ValidShells: shells}, users[0])
	assert.Equal(t, UserData{Username: "alice", UID: 501, GID: 20, Directory: "/Users/alice", Shell: "/bin/zsh", ValidShells: shells}, users[1])
}

func TestParseDsclUsers_IndentedMultiValue(t *testing.T) {
	// Given
	out := `NFSHomeDirectory:
 /Users/with space
PrimaryGroupID: 80
RecordName:
 root
 BUILTIN\Local System
UniqueID: 0
UserShell: /bin/sh
`

	// When
	users := parseDsclUsers(out, nil)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "root", users[0].Username)
	assert.Equal(t, "/Users/with space", users[0].Directory)
}

func TestParseDsclUsers_UsesFirstAlias(t *testing.T) {
	// Given
	out := "RecordName: _amavisd amavisd\nUniqueID: 83\nPrimaryGroupID: 83\n"

	// When
	users := parseDsclUsers(out, nil)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "_amavisd", users[0].Username)
}

func TestParseDsclUsers_InlineMultiValueUsesFirstValue(t *testing.T) {
	// Given
	out := "NFSHomeDirectory: /var/root /private/var/root\nRecordName: root\nUniqueID: 0\nUserShell: /bin/sh /bin/zsh\n"

	// When
	users := parseDsclUsers(out, nil)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "/var/root", users[0].Directory)
	assert.Equal(t, "/bin/sh", users[0].Shell)
}

func TestParseDsclUsers_UnparsableGIDFallsBackToZero(t *testing.T) {
	// Given
	out := "PrimaryGroupID: 9223372036854775808\nRecordName: alice\nUniqueID: 501\n"

	// When
	users := parseDsclUsers(out, nil)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, 0, users[0].GID)
}

func TestParseDsclUsers_MissingAttributesUseDefaults(t *testing.T) {
	// Given
	out := "RecordName: nobody\nUniqueID: -2\n"

	// When
	users := parseDsclUsers(out, nil)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, -2, users[0].UID)
	assert.Equal(t, 0, users[0].GID)
	assert.Empty(t, users[0].Directory)
	assert.Equal(t, utils.DefaultShell(), users[0].Shell)
}

func TestParseDsclUsers_SkipsBadUniqueID(t *testing.T) {
	// Given
	out := `RecordName: noid
-
RecordName: bad
UniqueID: abc
-
RecordName: good
UniqueID: 7
`

	// When
	users := parseDsclUsers(out, nil)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "good", users[0].Username)
}

func TestParseDsclUsers_EmptyOutput(t *testing.T) {
	// Given / When
	users := parseDsclUsers("", nil)

	// Then
	assert.Equal(t, []UserData{}, users)
}
