//go:build !linux && !windows

package file

import "strings"

func rootTransferOnProcfs(path string) (bool, error) {
	return path == "/proc" || strings.HasPrefix(path, "/proc/"), nil
}
