//go:build !windows

package executor

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// workingDirUsable reports whether a child running with attr's credentials can
// chdir into dir, which Go does after dropping privileges.
func workingDirUsable(dir string, attr *syscall.SysProcAttr) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	return attr == nil || attr.Credential == nil || dirSearchableBy(dir, attr.Credential)
}

// dirSearchableBy reports whether every directory on dir's resolved path grants
// cred search permission by its mode bits. ACLs are not read.
func dirSearchableBy(dir string, cred *syscall.Credential) bool {
	if cred.Uid == 0 {
		return true
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	for p := resolved; ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() || !searchable(info, cred) {
			return false
		}
		if p == filepath.Dir(p) {
			return true
		}
	}
}

// searchable applies the one permission class the kernel picks: owner, then
// group, then other.
func searchable(info os.FileInfo, cred *syscall.Credential) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := info.Mode().Perm()
	switch {
	case stat.Uid == cred.Uid:
		return perm&0o100 != 0
	case stat.Gid == cred.Gid || slices.Contains(cred.Groups, stat.Gid):
		return perm&0o010 != 0
	default:
		return perm&0o001 != 0
	}
}
