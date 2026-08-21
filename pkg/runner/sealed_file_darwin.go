package runner

import (
	"fmt"
	"os"
	"syscall"
)

// newSealedFile returns an empty file that no name in the filesystem refers to.
//
// macOS has no memfd, so the copy starts as a real file and is unlinked at
// once. It is created inside a private directory (os.MkdirTemp makes it 0700,
// owned by the agent) at mode 0600, so for the instant a name does exist no
// other account can reach it; after the unlink there is no name to reach.
func newSealedFile() (*os.File, error) {
	dir, err := os.MkdirTemp("", "alpamon-verified-")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSealUnavailable, err)
	}
	// Removed once the file inside is unlinked, leaving the object alive on
	// the descriptor alone.
	defer func() { _ = os.Remove(dir) }()

	file, err := os.CreateTemp(dir, "alpamon-verified-file")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSealUnavailable, err)
	}
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: failed to unlink the verified copy: %v", errSealUnavailable, err)
	}

	return file, nil
}

// sealFile confirms the copy is nameless, which is what stands in for sealing
// here.
//
// There is no F_SEAL_WRITE on macOS, so immutability cannot be enforced on the
// object itself; it comes from reachability instead. A link count of zero is
// the kernel's own statement that no directory entry points at this inode, so
// the requester—who knows only the original path—has nothing left to write to.
// The count is checked rather than assumed, for the same reason the seals are
// read back on Linux.
//
// The residue this leaves is narrower than the window it closes: the child
// this agent execs holds the descriptor and could write through it, because
// /dev/fd/N on macOS duplicates the descriptor (access mode included) instead
// of opening the object afresh, so a read-only handover is not available. That
// child is the approved script itself, so reaching the residue means the
// approver read and approved code that rewrites its own remaining bytes. The
// window being closed needed no such approval.
func sealFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%w: %v", errSealUnavailable, err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read the verified copy's link count", errSealUnavailable)
	}
	if stat.Nlink != 0 {
		return fmt.Errorf("%w: the verified copy still has %d link(s)", errSealUnavailable, stat.Nlink)
	}

	return nil
}
