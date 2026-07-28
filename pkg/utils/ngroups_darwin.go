package utils

import (
	"sync"

	"golang.org/x/sys/unix"
)

// darwinNGroupsMax is the fallback macOS setgroups(2) cap used when the
// kern.ngroups sysctl cannot be read. setgroups(2) returns EINVAL when the
// supplementary group list exceeds the kernel limit, which aborts privilege
// demotion just before execve and surfaces as "fork/exec ...: invalid
// argument". Accounts such as root belong to more than 16 groups on macOS, so
// the list must be truncated. macOS resolves group membership dynamically via
// opendirectoryd, so truncating the setgroups list does not change effective
// permissions.
const darwinNGroupsMax = 16

// maxSupplementaryGroups reads kern.ngroups, the limit the kernel reports and
// enforces in setgroups(2), falling back to darwinNGroupsMax if the sysctl
// cannot be read. The OID is read-only and derived from the compile-time
// NGROUPS_MAX, so the value cannot change while the process runs and is read
// once: privilege demotion happens on every command execution, not per session.
var maxSupplementaryGroups = sync.OnceValue(func() int {
	if n, err := unix.SysctlUint32("kern.ngroups"); err == nil && n > 0 {
		return int(n)
	}
	return darwinNGroupsMax
})
