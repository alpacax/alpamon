package utils

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// protectedDirSDDL makes Administrators the owner and grants full control to
// SYSTEM and Administrators, inherited
// by every file and subdirectory, and blocks inheritance from %ProgramData%,
// whose default ACL lets local users create files.
const protectedDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// SecureConfigDir creates the alpamon directory under %ProgramData% (which
// holds the configuration, data, log and run directories) and restricts its
// ACL to SYSTEM and Administrators.
//
// The ACL is applied to the directory and to everything already inside it,
// since an existing child keeps the ACEs it was created with.
func SecureConfigDir() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := restrictTreeACL(dir); err != nil {
		return err
	}
	configDirSecured.Store(true)
	return nil
}

var configDirSecured atomic.Bool

// ConfigDirSecured reports whether SecureConfigDir has succeeded in this
// process. Upgrade state is neither written nor acted on until it has.
func ConfigDirSecured() bool { return configDirSecured.Load() }

func restrictTreeACL(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Do not follow a link or junction out of the tree.
		if d.Type()&fs.ModeSymlink != 0 || d.Type()&fs.ModeIrregular != 0 {
			return fmt.Errorf("unexpected link %s in %s", path, root)
		}
		return restrictDirACL(path)
	})
}

// restrictDirACL sets the protected DACL on one file or directory.
func restrictDirACL(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDirSDDL)
	if err != nil {
		return fmt.Errorf("parse directory ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read directory ACL: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read directory owner: %w", err)
	}
	// The owner too: an owner can always rewrite the ACL, so whoever created
	// an entry beforehand must not keep owning it.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict ACL on %s: %w", dir, err)
	}
	return nil
}

// HandleOwnedByAdministrators reports whether the open file h is owned by
// SYSTEM or the Administrators group.
func HandleOwnedByAdministrators(h windows.Handle) (bool, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid), nil
}
