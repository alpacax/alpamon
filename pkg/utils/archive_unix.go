//go:build !windows

package utils

// symlinkUnsupported reports whether os.Symlink failed because the host makes no
// links at all. Nothing on Unix says only that: EPERM covers a filesystem without
// link support and a plain permission denial alike.
func symlinkUnsupported(error) bool { return false }
