//go:build !windows

package utils

// symlinkUnsupported reports whether os.Symlink failed because the host makes
// no links at all. On Unix nothing says only that: EPERM covers a filesystem
// without link support and a plain permission denial alike, so every failure
// here is reported.
func symlinkUnsupported(error) bool { return false }
