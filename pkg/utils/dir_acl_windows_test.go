package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestRestrictDirACL(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token: the restricted ACL admits only SYSTEM and Administrators")
	}
	dir := t.TempDir()
	require.NoError(t, restrictDirACL(dir))

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := sd.Control()
	require.NoError(t, err)
	assert.NotZero(t, control&windows.SE_DACL_PROTECTED, "inheritance from the parent is blocked")
	sddl := sd.String()
	assert.Contains(t, sddl, ";;;SY)")
	assert.Contains(t, sddl, ";;;BA)")
	assert.NotContains(t, sddl, ";;;BU)", "no access for local users")

	// A file created inside inherits the restricted ACL.
	f := filepath.Join(dir, "child")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	child, err := windows.GetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	assert.NotContains(t, child.String(), ";;;BU)")
}
