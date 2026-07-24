//go:build !windows

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveGroups_PrimaryGidFirstNoCap(t *testing.T) {
	// gid 20 already present in the list; it must be hoisted to the front and deduped.
	groups, inList, err := resolveGroups(20, []string{"80", "20", "12"}, 0)
	require.NoError(t, err)
	assert.True(t, inList)
	assert.Equal(t, []uint32{20, 80, 12}, groups)
}

func TestResolveGroups_TruncatesToMaxKeepingPrimaryGid(t *testing.T) {
	groupIds := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
		"11", "12", "13", "14", "15", "16", "17", "18", "19", "20"}

	groups, _, err := resolveGroups(99, groupIds, 16)
	require.NoError(t, err)
	// Primary gid stays at the front and the first 15 supplementary entries
	// survive in order; ids 16-20 are dropped by the cap.
	assert.Equal(t, []uint32{99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, groups)
}

func TestResolveGroups_GroupNotInList(t *testing.T) {
	groups, inList, err := resolveGroups(99, []string{"80", "12"}, 0)
	require.NoError(t, err)
	assert.False(t, inList)
	// Primary gid is still prepended so it survives setgroups.
	assert.Equal(t, uint32(99), groups[0])
}

func TestResolveGroups_InvalidGidString(t *testing.T) {
	_, _, err := resolveGroups(20, []string{"not-a-number"}, 0)
	assert.Error(t, err)
}
