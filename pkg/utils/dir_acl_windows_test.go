package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestRestrictTreeACL_CoversExistingChildren(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token: the restricted ACL admits only SYSTEM and Administrators")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	require.NoError(t, os.Mkdir(data, 0o700))
	// A pre-existing child with its own explicit ACE for local users.
	users, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;BU)")
	require.NoError(t, err)
	dacl, _, err := users.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(data, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil))

	require.NoError(t, restrictTreeACL(root))
	sd, err := windows.GetNamedSecurityInfo(data, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	assert.NotContains(t, sd.String(), ";;;BU)")
}

// enablePrivilege enables name on the process token, failing the test when it
// cannot.
func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token))
	defer func() { _ = token.Close() }()
	var luid windows.LUID
	require.NoError(t, windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid))
	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	require.NoError(t, windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil), "enable %s", name)
}

// TestRestrictTreeACL_TakesOwnership pre-creates an entry owned by a
// non-administrative principal and checks the step takes ownership back.
// It runs on every elevated token and skips only on an unelevated one.
func TestRestrictTreeACL_TakesOwnership(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token")
	}
	root := t.TempDir()
	child := filepath.Join(root, "data")
	require.NoError(t, os.Mkdir(child, 0o700))
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)
	// Giving an entry an owner the caller is not needs the restore
	// privilege, which an elevated token holds but has disabled.
	enablePrivilege(t, "SeRestorePrivilege")
	require.NoError(t, windows.SetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil),
		"pre-create an entry owned by Users")

	require.NoError(t, restrictTreeACL(root))
	sd, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	assert.True(t, owner.IsWellKnown(windows.WinBuiltinAdministratorsSid), "owner is %s", owner)
}

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
