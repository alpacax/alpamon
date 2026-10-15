package runner

import (
	"errors"
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

func TestUserFromRecord_UnparsableGIDFallsBackToZero(t *testing.T) {
	// Given
	rec := map[string]string{"RecordName": "alice", "UniqueID": "501", "PrimaryGroupID": "9223372036854775808"}

	// When
	user, ok := userFromRecord(rec, nil)

	// Then
	require.True(t, ok)
	assert.Equal(t, 0, user.GID)
}

func TestUserFromRecord_MissingAttributesUseDefaults(t *testing.T) {
	// Given
	rec := map[string]string{"RecordName": "nobody", "UniqueID": "-2"}

	// When
	user, ok := userFromRecord(rec, nil)

	// Then
	require.True(t, ok)
	assert.Equal(t, -2, user.UID)
	assert.Equal(t, 0, user.GID)
	assert.Empty(t, user.Directory)
	assert.Equal(t, utils.DefaultShell(), user.Shell)
}

func TestUserFromRecord_RejectsRecordWithoutNameOrNumericUID(t *testing.T) {
	tests := []struct {
		name string
		rec  map[string]string
	}{
		{"no name", map[string]string{"UniqueID": "501"}},
		{"no UniqueID", map[string]string{"RecordName": "alice"}},
		{"non-numeric UniqueID", map[string]string{"RecordName": "alice", "UniqueID": "abc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			_, ok := userFromRecord(tt.rec, nil)

			// Then
			assert.False(t, ok)
		})
	}
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
	tests := []struct {
		name string
		out  string
		attr string
	}{
		{"inline", "RecordName: root\nUniqueID: 0\nRecordName: alice\nUniqueID: 501\n", "RecordName"},
		{"indented", "RecordName:\n root\n BUILTIN\\Local System\nUniqueID: 0\nRecordName:\n alice\n", "RecordName"},
		{"valueless first", "RecordName: root\nUniqueID: 0\nUserShell:\nUserShell: /bin/zsh\n", "UserShell"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			users, err := parseDsclUsers(tt.out, nil)

			// Then
			assert.ErrorContains(t, err, tt.attr)
			assert.Nil(t, users)
		})
	}
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

func TestGetUserData_WarnsWhenDsclFails(t *testing.T) {
	// Given
	logs := captureLogs(t)
	stubCollectCommand(t, errors.New("dscl timed out after 30s"))

	// When
	users, err := getUserData()

	// Then
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, logs.String(), `"level":"warn"`)
	assert.Contains(t, logs.String(), "users will not be reported")
}

func TestGetGroupData_WarnsWhenDsclFails(t *testing.T) {
	// Given
	logs := captureLogs(t)
	stubCollectCommand(t, errors.New("dscl timed out after 30s"))

	// When
	groups, err := getGroupData()

	// Then
	require.Error(t, err)
	assert.Nil(t, groups)
	assert.Contains(t, logs.String(), `"level":"warn"`)
	assert.Contains(t, logs.String(), "groups will not be reported")
}

func stubCollectCommand(t *testing.T, err error) {
	t.Helper()
	previous := runCollectCommand
	t.Cleanup(func() { runCollectCommand = previous })
	runCollectCommand = func(string, ...string) ([]byte, error) { return nil, err }
}
