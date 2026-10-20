//go:build !windows

package utils

import (
	"math"
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDemoteValidatesGroup(t *testing.T) {
	oldUID, oldUser, oldGroup, oldIDs := demoteGetuid, demoteLookupUser, demoteLookupGroup, demoteGroupIDs
	t.Cleanup(func() {
		demoteGetuid, demoteLookupUser, demoteLookupGroup, demoteGroupIDs = oldUID, oldUser, oldGroup, oldIDs
	})

	for _, uid := range []int{0, 1000} {
		for _, tt := range []struct {
			name, group, gid string
			ids              []string
			wantErr          string
		}{
			{name: "primary member", group: "primary", gid: "1000", ids: []string{"2000"}},
			{name: "supplementary member", group: "shared", gid: "2000", ids: []string{"1000", "2000"}},
			{name: "non-member", group: "other", gid: "3000", ids: []string{"1000", "2000"}, wantErr: "groupname other is not in user account's group list"},
			{name: "unknown group", group: "missing", wantErr: "there is no corresponding missing groupname in this server"},
			{name: "empty group", wantErr: "groupname is required"},
		} {
			t.Run(strconv.Itoa(uid)+"/"+tt.name, func(t *testing.T) {
				demoteGetuid = func() int { return uid }
				demoteLookupUser = func(name string) (*user.User, error) {
					require.NotEmpty(t, tt.group, "empty group must fail before lookup")
					return &user.User{Username: name, Uid: "1000", Gid: "1000", HomeDir: "/home/account"}, nil
				}
				demoteLookupGroup = func(name string) (*user.Group, error) {
					if tt.gid == "" {
						return nil, user.UnknownGroupError(name)
					}
					return &user.Group{Name: name, Gid: tt.gid}, nil
				}
				demoteGroupIDs = func(*user.User) ([]string, error) { return tt.ids, nil }
				result, err := Demote("account", tt.group, DemoteOptions{ValidateGroup: true})
				if tt.wantErr != "" {
					require.EqualError(t, err, tt.wantErr)
					assert.Nil(t, result)
				} else {
					require.NoError(t, err)
					if uid == 0 {
						require.NotNil(t, result)
						assert.Equal(t, tt.gid, strconv.FormatUint(uint64(result.SysProcAttr.Credential.Gid), 10))
					} else {
						assert.Nil(t, result, "non-root execution retains current credentials")
					}
				}
			})
		}
	}
}

func TestDemoteRootRequiresGroupWithoutValidation(t *testing.T) {
	oldUID := demoteGetuid
	t.Cleanup(func() { demoteGetuid = oldUID })
	demoteGetuid = func() int { return 0 }
	result, err := Demote("account", "", DemoteOptions{})
	assert.EqualError(t, err, "groupname is required")
	assert.Nil(t, result)
}

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
			// Without dedup the repeated 80 would eat a cap slot and push 12 out.
			name: "duplicate supplementary gids deduped before capping", gid: 99,
			groupIds: []string{"80", "80", "12"}, maxGroups: 3,
			want: []uint32{99, 80, 12},
		},
		{
			name: "no supplementary groups keeps only the primary gid", gid: 0,
			groupIds: nil,
			want:     []uint32{0},
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

func TestDemotedSysProcAttr(t *testing.T) {
	tests := []struct {
		name       string
		uid        uint32
		gid        uint32
		groupIds   []string
		wantGroups []uint32
		wantInList bool
		wantErr    bool
	}{
		{
			name: "assembles credential with resolved groups", uid: 501, gid: 20,
			groupIds:   []string{"80", "20", "12"},
			wantGroups: []uint32{20, 80, 12}, wantInList: true,
		},
		{
			// Non-membership is reported, not rejected: enforcing it is the
			// caller's choice via DemoteOptions.ValidateGroup.
			name: "reports non-member group without failing", uid: 501, gid: 99,
			groupIds:   []string{"80"},
			wantGroups: []uint32{99, 80},
		},
		{
			// Must fail the demotion, not silently drop the gid as the old paths did.
			name: "unparsable group id is an error", uid: 501, gid: 20,
			groupIds: []string{"nope"}, wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, inList, err := demotedSysProcAttr(tt.uid, tt.gid, tt.groupIds)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, attr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, attr)
			require.NotNil(t, attr.Credential)
			assert.Equal(t, tt.uid, attr.Credential.Uid)
			assert.Equal(t, tt.gid, attr.Credential.Gid)
			assert.Equal(t, tt.wantGroups, attr.Credential.Groups)
			assert.Equal(t, tt.wantInList, inList)
		})
	}
}

func TestDemotedSysProcAttr_AppliesPlatformCap(t *testing.T) {
	groupIds := make([]string, 0, 64)
	for i := 1; i <= 64; i++ {
		groupIds = append(groupIds, strconv.Itoa(i))
	}

	attr, err := DemotedSysProcAttr(501, 99, groupIds)
	require.NoError(t, err)
	require.NotNil(t, attr)
	require.NotNil(t, attr.Credential)

	// The exported entry point must apply maxSupplementaryGroups(); anything
	// larger would make setgroups(2) fail with EINVAL on a capped platform.
	groups := attr.Credential.Groups
	if cap := maxSupplementaryGroups(); cap > 0 {
		assert.Len(t, groups, cap)
	} else {
		assert.Len(t, groups, len(groupIds)+1)
	}
	assert.Equal(t, uint32(99), groups[0])
}
