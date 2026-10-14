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
	users, err := parseDsclUsers(out, shells)
	require.NoError(t, err)

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
	users, err := parseDsclUsers(out, nil)
	require.NoError(t, err)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "root", users[0].Username)
	assert.Equal(t, "/Users/with space", users[0].Directory)
}

func TestParseDsclUsers_UsesFirstAlias(t *testing.T) {
	// Given
	out := "RecordName: _amavisd amavisd\nUniqueID: 83\nPrimaryGroupID: 83\n"

	// When
	users, err := parseDsclUsers(out, nil)
	require.NoError(t, err)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "_amavisd", users[0].Username)
}

func TestParseDsclUsers_InlineMultiValueUsesFirstValue(t *testing.T) {
	// Given
	out := "NFSHomeDirectory: /var/root /private/var/root\nRecordName: root\nUniqueID: 0\nUserShell: /bin/sh /bin/zsh\n"

	// When
	users, err := parseDsclUsers(out, nil)
	require.NoError(t, err)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "/var/root", users[0].Directory)
	assert.Equal(t, "/bin/sh", users[0].Shell)
}

func TestParseDsclUsers_UnparsableGIDFallsBackToZero(t *testing.T) {
	// Given
	out := "PrimaryGroupID: 9223372036854775808\nRecordName: alice\nUniqueID: 501\n"

	// When
	users, err := parseDsclUsers(out, nil)
	require.NoError(t, err)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, 0, users[0].GID)
}

func TestParseDsclUsers_MissingAttributesUseDefaults(t *testing.T) {
	// Given
	out := "RecordName: nobody\nUniqueID: -2\n"

	// When
	users, err := parseDsclUsers(out, nil)
	require.NoError(t, err)

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
	users, err := parseDsclUsers(out, nil)
	require.NoError(t, err)

	// Then
	require.Len(t, users, 1)
	assert.Equal(t, "good", users[0].Username)
}

func TestParseDsclUsers_EmptyOutput(t *testing.T) {
	// Given / When
	users, err := parseDsclUsers("", nil)
	require.NoError(t, err)

	// Then
	assert.Equal(t, []UserData{}, users)
}

func TestParseDsclUsers_RepeatedAttributeIsAnError(t *testing.T) {
	// Given
	out := "RecordName: root\nUniqueID: 0\nRecordName: alice\nUniqueID: 501\n"

	// When
	users, err := parseDsclUsers(out, nil)

	// Then
	assert.ErrorContains(t, err, "RecordName")
	assert.Nil(t, users)
}

func TestParseDsclUsers_RepeatedIndentedAttributeIsAnError(t *testing.T) {
	// Given
	out := "RecordName:\n root\n BUILTIN\\Local System\nUniqueID: 0\nRecordName:\n alice\n"

	// When
	users, err := parseDsclUsers(out, nil)

	// Then
	assert.ErrorContains(t, err, "RecordName")
	assert.Nil(t, users)
}

func TestUsersFromDscl_WarnsWhenOutputDoesNotParse(t *testing.T) {
	// Given
	logs := captureLogs(t)
	out := []byte("RecordName: root\nUniqueID: 0\nRecordName: alice\nUniqueID: 501\n")

	// When
	_, err := usersFromDscl(out)

	// Then
	require.Error(t, err)
	assert.Contains(t, logs.String(), `"level":"warn"`)
	assert.Contains(t, logs.String(), "repeats RecordName")
}
