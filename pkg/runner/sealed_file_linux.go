package runner

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// verifiedFileSeals makes the copy permanently immutable: no writes, and no
// change of length in either direction. F_SEAL_SEAL closes the door behind
// them so nothing—including this process—can lift the others later.
const verifiedFileSeals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL

// newSealedFile returns an empty anonymous memory file.
//
// It exists only as a descriptor: it has no name anywhere in the filesystem,
// so the requester has nothing to open, rename or rewrite. MFD_CLOEXEC keeps
// it out of unrelated children—os/exec clears close-on-exec on the descriptor
// it dups into the child that is meant to have it.
func newSealedFile() (*os.File, error) {
	fd, err := unix.MemfdCreate("alpamon-verified-file", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("%w: memfd_create: %v", errSealUnavailable, err)
	}
	return os.NewFile(uintptr(fd), "memfd:alpamon-verified-file"), nil
}

// sealFile makes file's contents immutable for every descriptor that refers to
// it, this process's own included.
//
// The seals are read back rather than assumed: a memfd created without
// MFD_ALLOW_SEALING, or on a kernel that took the request without honoring it,
// would leave the copy writable and put the swap window straight back. An
// unverified seal is the same hole wearing a different name, so a readback
// that does not show every seal refuses the command.
func sealFile(file *os.File) error {
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, verifiedFileSeals); err != nil {
		return fmt.Errorf("%w: failed to seal the verified copy: %v", errSealUnavailable, err)
	}

	applied, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to read back the seals: %v", errSealUnavailable, err)
	}
	if applied&verifiedFileSeals != verifiedFileSeals {
		return fmt.Errorf("%w: seals not applied (want 0x%x, got 0x%x)",
			errSealUnavailable, verifiedFileSeals, applied)
	}

	return nil
}
