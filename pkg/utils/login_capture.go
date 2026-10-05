package utils

// LoginCapture tells the server whether logins that reach this host without
// Alpacon (SSH, the console, su) are captured by the Alpamon PAM session
// hook. It rides the system-info report as the login_capture key.
//
// The server reads schema, pam_module and hooks.sshd, hooks.login and
// hooks.su as required, hooks.su-l and sshd_use_pam as optional, and ignores
// keys it does not know. A host reads as covered only when every piece holds,
// so a value here must never claim more than the collector established.
type LoginCapture struct {
	Schema    int               `json:"schema"`
	PAMModule string            `json:"pam_module"`
	Hooks     LoginCaptureHooks `json:"hooks"`
	// SSHDUsePAM is sshd's effective UsePAM, "yes" or "no", or null when sshd
	// is not installed or the setting could not be determined.
	SSHDUsePAM *string `json:"sshd_use_pam"`
}

// LoginCaptureHooks holds one Hook* value per login service. SuL is empty,
// and so omitted, unless the host has a PAM file of its own for su-l.
type LoginCaptureHooks struct {
	SSHD  string `json:"sshd"`
	Login string `json:"login"`
	Su    string `json:"su"`
	SuL   string `json:"su-l,omitempty"`
}

const (
	loginCaptureSchema = 1

	PAMModulePresent = "present"
	PAMModuleMissing = "missing"

	// HookRegistered: a session line loading the module is reachable from
	// the service's PAM file.
	HookRegistered = "registered"
	// HookMissing: the service's PAM file exists but no such line is
	// reachable from it.
	HookMissing = "missing"
	// HookNotApplicable: neither a PAM file nor a binary for the service.
	HookNotApplicable = "not_applicable"
	// HookUnreadable: the PAM file or a file it includes could not be read or
	// resolved, or the service's binary exists without any PAM file.
	HookUnreadable = "unreadable"
)
