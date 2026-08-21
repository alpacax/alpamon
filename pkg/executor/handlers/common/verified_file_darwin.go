package common

import "fmt"

// VerifiedFilePath returns the child-visible path naming the inherited,
// digest-verified descriptor.
//
// macOS has no /proc, but opening /dev/fd/N duplicates the descriptor rather
// than resolving the original path again, which preserves the same property:
// a file swapped in at the path after verification is not what runs. The
// duplicate shares the descriptor's offset, which is why the verifier rewinds
// it after hashing.
func VerifiedFilePath() (string, error) {
	return fmt.Sprintf("/dev/fd/%d", VerifiedFileChildFD), nil
}
