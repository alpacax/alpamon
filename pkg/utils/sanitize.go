package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SanitizePath validates and cleans a file path to prevent path traversal.
// It resolves the path to an absolute form and ensures it does not escape
// the filesystem root. Returns the cleaned absolute path.
func SanitizePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		abs, err := filepath.Abs(cleaned)
		if err != nil {
			return "", fmt.Errorf("failed to resolve path: %w", err)
		}
		cleaned = abs
	}
	// Reject paths containing traversal after cleaning
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal detected: %s", path)
	}
	return cleaned, nil
}
