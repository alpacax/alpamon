package utils

import "fmt"

// AuditOutputCap bounds command output retained for the fin audit payload.
const AuditOutputCap = 1 << 20 // 1 MiB

// TruncateMiddle keeps s's first and last halves within max bytes, replacing the
// dropped middle with a marker. It returns s unchanged when already within max.
func TruncateMiddle(s string, max int) string {
	if len(s) <= max {
		return s
	}
	head := max / 2
	tail := max - head
	dropped := len(s) - head - tail
	return s[:head] + fmt.Sprintf("\n... [%d bytes truncated] ...\n", dropped) + s[len(s)-tail:]
}
