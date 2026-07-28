package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The darwinNGroupsMax fallback would mask a misspelled OID, leaving the
// runtime read dead with nothing to notice, so assert the sysctl itself.
func TestMaxSupplementaryGroups_ReadsSysctl(t *testing.T) {
	n, err := unix.SysctlUint32("kern.ngroups")
	require.NoError(t, err, "kern.ngroups must be readable on darwin")
	require.NotZero(t, n)

	assert.Equal(t, int(n), maxSupplementaryGroups())
}
