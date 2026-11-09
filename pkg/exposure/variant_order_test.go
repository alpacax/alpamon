package exposure

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVariantSortPreservesCanonicalOrder(t *testing.T) {
	values := []authorization{
		{Count: 2, Role: "user_key", Options: []string{"no-pty"}},
		{Count: 10, Role: "user_key", Options: []string{"restrict"}},
		{Count: 1, Role: "cert_authority", Comment: ptr("z")},
		{Count: 1, Role: "user_key", Comment: ptr("a")},
	}
	want := slices.Clone(values)
	slices.SortFunc(want, func(a, b authorization) int {
		left, err := encodeValue(a)
		require.NoError(t, err)
		right, err := encodeValue(b)
		require.NoError(t, err)
		return bytes.Compare(left, right)
	})
	ids := map[string]int{}
	for i, a := range values {
		ids[variantID(a)] = i
	}
	sortAuthorizations(values, ids)
	assert.Equal(t, want, values)
}

func TestSudoRepeatedAliasExpansionStaysBounded(t *testing.T) {
	for _, kind := range []string{"User_Alias", "Runas_Alias", "Cmnd_Alias"} {
		first := "alice"
		if kind == "Cmnd_Alias" {
			first = "/bin/cat"
		}
		policy := kind + " A0 = " + first + "\n"
		for i := 1; i <= 24; i++ {
			policy += fmt.Sprintf("%s A%d = A%d, A%d\n", kind, i, i-1, i-1)
		}
		switch kind {
		case "User_Alias":
			policy += "A24 ALL=ALL"
		case "Runas_Alias":
			policy += "alice ALL=(A24) ALL"
		case "Cmnd_Alias":
			policy += "alice ALL=A24"
		}
		result := sudoFor(t, policy, "alice")
		require.True(t, result.Complete, kind)
		require.Len(t, result.Grants, 1)
		if kind == "Runas_Alias" {
			assert.Equal(t, "alice", result.Grants[0].Runas)
		}
	}
}
