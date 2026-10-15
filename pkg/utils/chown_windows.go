//go:build windows

package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// ChownRecursive walks path as on Unix; chown is not meaningful on Windows.
func ChownRecursive(path string, uid, gid int) error {
	if path == "" {
		return fmt.Errorf("path must not be empty")
	}
	path = filepath.Clean(path)
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		return os.Chown(p, uid, gid)
	})
}
