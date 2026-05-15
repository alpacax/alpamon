package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SanitizePath validates and cleans a file path to prevent path traversal
// and other unsafe shapes. Returns the cleaned absolute native path.
//
// Rejected inputs:
//   - paths containing a null byte (would truncate at the OS boundary and
//     bypass logging that captures the full string)
//   - paths whose cleaned form retains a literal ".." (post-Clean traversal)
//   - paths whose cleaned form starts with `\\` (Windows UNC, local device,
//     and extended-length namespaces: `\\server\share`, `\\.\PHYSICALDRIVE0`,
//     `\\?\...`, `\\?\UNC\...`). These have no legitimate WebFTP use; an
//     attacker who can supply wire input could otherwise make alpamon
//     (running as SYSTEM on Windows) authenticate to a hostile SMB server
//     or open raw devices. The prefix has no legitimate meaning on Unix
//     either, so the check is universal — no platform branch needed.
func SanitizePath(path string) (string, error) {
	if strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("invalid argument: path contains null byte")
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		abs, err := filepath.Abs(cleaned)
		if err != nil {
			return "", fmt.Errorf("failed to resolve path: %w", err)
		}
		cleaned = abs
	}
	if strings.HasPrefix(cleaned, `\\`) {
		return "", fmt.Errorf("invalid argument: UNC and device paths are not allowed: %s", path)
	}
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal detected: %s", path)
	}
	return cleaned, nil
}
