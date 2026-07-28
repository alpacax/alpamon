//go:build !windows

package utils

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveGroups(t *testing.T) {
	tests := []struct {
		name       string
		gid        uint32
		groupIds   []string
		maxGroups  int
		want       []uint32
		wantInList bool
		wantErr    bool
	}{
		{
			// gid 20 already present in the list; it must be hoisted to the front and deduped.
			name: "primary gid hoisted and deduped", gid: 20,
			groupIds: []string{"80", "20", "12"},
			want:     []uint32{20, 80, 12}, wantInList: true,
		},
		{
			// Primary gid is still prepended so it survives setgroups.
			name: "primary gid prepended when not a member", gid: 99,
			groupIds: []string{"80", "12"},
			want:     []uint32{99, 80, 12},
		},
		{
			// Primary gid stays at the front and the first 15 supplementary entries
			// survive in order; ids 16-20 are dropped by the cap.
			name: "truncates to cap keeping primary gid", gid: 99,
			groupIds: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
				"11", "12", "13", "14", "15", "16", "17", "18", "19", "20"},
			maxGroups: 16,
			want:      []uint32{99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		{
			name: "exactly at cap keeps every entry", gid: 99,
			groupIds: []string{"1", "2"}, maxGroups: 3,
			want: []uint32{99, 1, 2},
		},
		{
			name: "cap of one keeps only the primary gid", gid: 99,
			groupIds: []string{"1", "2"}, maxGroups: 1,
			want: []uint32{99},
		},
		{
			name: "max uint32 accepted", gid: 20,
			groupIds: []string{"4294967295"},
			want:     []uint32{20, math.MaxUint32},
		},
		{
			name: "negative gid rejected", gid: 20,
			groupIds: []string{"1000", "-1"}, wantErr: true,
		},
		{
			name: "overflowing gid rejected", gid: 20,
			groupIds: []string{"4294967296"}, wantErr: true,
		},
		{
			name: "empty gid rejected", gid: 20,
			groupIds: []string{""}, wantErr: true,
		},
		{
			name: "non-numeric gid rejected", gid: 20,
			groupIds: []string{"not-a-number"}, wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups, inList, err := resolveGroups(tt.gid, tt.groupIds, tt.maxGroups)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, groups)
			assert.Equal(t, tt.wantInList, inList)
		})
	}
}

func TestResolveGroups_AppliesPlatformCap(t *testing.T) {
	groupIds := make([]string, 0, 64)
	for i := 1; i <= 64; i++ {
		groupIds = append(groupIds, strconv.Itoa(i))
	}

	groups, _, err := ResolveGroups(99, groupIds)
	require.NoError(t, err)

	// The exported entry point must apply maxSupplementaryGroups(); anything
	// larger would make setgroups(2) fail with EINVAL on a capped platform.
	if cap := maxSupplementaryGroups(); cap > 0 {
		assert.Len(t, groups, cap)
	} else {
		assert.Len(t, groups, len(groupIds)+1)
	}
	assert.Equal(t, uint32(99), groups[0])
}
