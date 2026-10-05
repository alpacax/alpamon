//go:build !linux

package utils

// GetLoginCapture returns nil off Linux, where there is no PAM session hook
// to report on, so the report goes out without the block.
func GetLoginCapture() *LoginCapture {
	return nil
}
