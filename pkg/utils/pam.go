package utils

// sudoPAMDisabled controls whether sudo PAM approval functionality is enabled.
// When true, the control client and auth manager will not be started.
// This is useful for testing environments or releases where the server-side
// control endpoint is not yet available.
var sudoPAMDisabled = false

// IsSudoPAMDisabled returns whether sudo PAM functionality is disabled.
func IsSudoPAMDisabled() bool {
	return sudoPAMDisabled
}
