package common

import "fmt"

// VerifiedFilePath returns the child-visible path naming the inherited,
// digest-verified descriptor.
//
// Opening /proc/self/fd/N reopens the very inode the descriptor holds instead
// of resolving the original path a second time. That is the whole point: a
// file swapped in at the path after verification is a different inode, so it
// cannot be substituted for the bytes that were hashed.
//
// The reopen re-checks permissions against that inode, so the entrypoint must
// be readable by the user the command runs as. A file the target user cannot
// read fails the reopen outright rather than running something else.
func VerifiedFilePath() (string, error) {
	return fmt.Sprintf("/proc/self/fd/%d", VerifiedFileChildFD), nil
}
