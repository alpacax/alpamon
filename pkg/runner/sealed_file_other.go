//go:build !linux && !darwin

package runner

import (
	"fmt"
	"os"
	"runtime"
)

// newSealedFile declines on platforms with no way to hold the verified bytes
// beyond the requester's reach.
//
// common.VerifiedFilePath already turns these hosts away before a file is ever
// opened, so this is the second of two closed doors rather than the only one.
func newSealedFile() (*os.File, error) {
	return nil, fmt.Errorf("%w on %s", errSealUnavailable, runtime.GOOS)
}

// sealFile is unreachable here: newSealedFile never returns a file to seal.
func sealFile(*os.File) error {
	return fmt.Errorf("%w on %s", errSealUnavailable, runtime.GOOS)
}
