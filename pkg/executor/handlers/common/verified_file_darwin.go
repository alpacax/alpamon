package common

import "fmt"

// VerifiedFilePath returns the child-visible path naming the inherited,
// digest-verified descriptor.
//
// The descriptor does not refer to the file on disk. It refers to the unlinked
// copy the agent made once the digest matched, and macOS resolves /dev/fd/N by
// duplicating the descriptor rather than by walking a path, so neither
// replacing the original nor rewriting it in place changes what the child
// reads. The duplicate shares the descriptor's offset, which is why the
// verifier rewinds it after hashing.
//
// Two consequences are deliberate. The copy belongs to the agent, so the
// source file's mode no longer gates who may run it—see the Linux counterpart
// for why that trade is the intended one. And because /dev/fd duplicates the
// descriptor's access mode, the child can write to the copy through its own
// descriptor; runner.sealFile documents why that residue is narrower than the
// window the copy closes.
func VerifiedFilePath() (string, error) {
	return fmt.Sprintf("/dev/fd/%d", VerifiedFileChildFD), nil
}
