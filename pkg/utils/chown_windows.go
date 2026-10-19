//go:build windows

package utils

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ChownRecursive is unsupported on Windows, which has no uid/gid ownership.
func ChownRecursive(path string, uid, gid, linkOwner int) (skipped int, err error) {
	if path == "" {
		return 0, errors.New("path must not be empty")
	}
	return 0, fmt.Errorf("chown %s: %w", filepath.Clean(path), errors.ErrUnsupported)
}
