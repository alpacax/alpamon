//go:build windows

package utils

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ChownRecursive is unsupported on Windows, which has no uid/gid ownership.
func ChownRecursive(path string, uid, gid int) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	return fmt.Errorf("chown %s: %w", filepath.Clean(path), errors.ErrUnsupported)
}
