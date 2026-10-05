//go:build linux

package utils

var defaultLoginCapture = newLoginCaptureCollector("/")

// GetLoginCapture returns the login_capture block for this host, or nil when
// the check failed or did not finish within its deadline, in which case the
// report goes out without it. It never panics and is cheap to call on every
// report: PAM files are re-read and sshd -T re-run only when what they depend
// on changed.
func GetLoginCapture() *LoginCapture {
	return defaultLoginCapture.Get()
}
