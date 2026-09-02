//go:build !linux && !darwin

package common

import (
	"fmt"
	"runtime"
)

// VerifiedFilePath declines on platforms with no path form that reopens the
// descriptor itself.
//
// Naming the original path instead would let the file be swapped between the
// digest check and the exec, which is exactly the attack the digest exists to
// close, so the handler refuses rather than running unverified bytes.
func VerifiedFilePath() (string, error) {
	return "", fmt.Errorf("file execution is not supported on %s: no path form reopens the verified descriptor", runtime.GOOS)
}
