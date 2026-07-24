package utils

import "golang.org/x/sys/unix"

// darwinNGroupsMax is the fallback macOS setgroups(2) cap used when the
// kern.ngroups sysctl cannot be read. setgroups(2) returns EINVAL when the
// supplementary group list exceeds the kernel limit, which aborts privilege
// demotion just before execve and surfaces as "fork/exec ...: invalid
// argument". Accounts such as root belong to more than 16 groups on macOS, so
// the list must be truncated. macOS resolves group membership dynamically via
// opendirectoryd, so truncating the setgroups list does not change effective
// permissions.
const darwinNGroupsMax = 16

// maxSupplementaryGroups reads kern.ngroups, the runtime-tunable limit the
// kernel actually enforces in setgroups(2), falling back to darwinNGroupsMax
// if the sysctl cannot be read.
func maxSupplementaryGroups() int {
	if n, err := unix.SysctlUint32("kern.ngroups"); err == nil && n > 0 {
		return int(n)
	}
	return darwinNGroupsMax
}
