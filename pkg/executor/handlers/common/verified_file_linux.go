package common

import "fmt"

// VerifiedFilePath returns the child-visible path naming the inherited,
// digest-verified descriptor.
//
// The descriptor does not refer to the file on disk. It refers to the sealed
// anonymous copy the agent made once the digest matched, so opening
// /proc/self/fd/N reopens that copy: an object with no name for the requester
// to replace, and sealed against writes even through the descriptors that
// already exist. Neither replacing the original path nor rewriting it in place
// changes what the child reads.
//
// One consequence is deliberate and worth stating plainly, because it changes
// existing behavior: the copy belongs to the agent, so the kernel's permission
// check on reopen is against the copy rather than against the source file's
// mode. A script only root can read therefore becomes executable as a demoted
// account, which was not true while the descriptor pointed at the original
// inode. That is the intended trade—the approval is the authorization on this
// lane, and the approver saw the content and named the account it runs as.
func VerifiedFilePath() (string, error) {
	return fmt.Sprintf("/proc/self/fd/%d", VerifiedFileChildFD), nil
}
