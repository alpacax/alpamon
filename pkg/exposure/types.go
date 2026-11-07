package exposure

// SchemaVersion is the report schema this agent sends.
const SchemaVersion = 1

// Category names: the eight keys of the report's categories object.
const (
	catAccounts     = "accounts"
	catPasswords    = "passwords"
	catKeys         = "keys"
	catCertificates = "certificates"
	catTrust        = "trust"
	catSudo         = "sudo"
	catSSHD         = "sshd"
	catPTY          = "pty_history"
)

var categoryNames = []string{
	catAccounts, catPasswords, catKeys, catCertificates,
	catTrust, catSudo, catSSHD, catPTY,
}

// Coverage status values.
const (
	coverageCovered = "covered"
	coveragePartial = "partial"
	coverageUnknown = "unknown"
)

// Source envelope status values.
const (
	statusRead       = "read"
	statusAbsent     = "absent"
	statusUnreadable = "unreadable"
	statusRejected   = "rejected"
	statusUnresolved = "unresolved"
	statusTimeout    = "timeout"
)

// Reason codes. The server rejects any code outside this closed list.
const (
	reasonFileUnreadable          = "file_unreadable"
	reasonFileRejected            = "file_rejected"
	reasonParseError              = "parse_error"
	reasonLimitExceeded           = "limit_exceeded"
	reasonConcurrentChange        = "concurrent_change"
	reasonTimeout                 = "timeout"
	reasonHomeUnreadable          = "home_unreadable"
	reasonPathTokenUnresolved     = "path_token_unresolved"
	reasonStrictModesUnresolved   = "strict_modes_unresolved"
	reasonSSHDNotInstalled        = "sshd_not_installed"
	reasonSSHDUnavailable         = "sshd_unavailable"
	reasonSSHDConfigUnresolved    = "sshd_config_unresolved"
	reasonSSHDMatchConditional    = "sshd_match_conditional"
	reasonSSHDMatchUnsupported    = "sshd_match_unsupported"
	reasonRevocationUnresolved    = "revocation_unresolved"
	reasonPAMBackendUnresolved    = "pam_backend_unresolved"
	reasonKerberosMappingUnresolv = "kerberos_mapping_unresolved"
	reasonHostbasedConditional    = "hostbased_conditional"
	reasonHostbasedUnassessed     = "hostbased_unassessed"
	reasonSudoUnsupportedSyntax   = "sudo_unsupported_syntax"
	reasonSudoHostConditional     = "sudo_host_conditional"
	reasonSudoPolicyUnresolved    = "sudo_policy_unresolved"
	reasonExternalSource          = "external_source"
	reasonPTYSourceAbsent         = "pty_source_absent"
	reasonPTYSourceUnsupported    = "pty_source_unsupported"
)

// agentReasons is every code an agent may send.
var agentReasons = map[string]bool{
	reasonFileUnreadable: true, reasonFileRejected: true, reasonParseError: true,
	reasonLimitExceeded: true, reasonConcurrentChange: true, reasonTimeout: true,
	reasonHomeUnreadable: true, reasonPathTokenUnresolved: true,
	reasonStrictModesUnresolved: true, reasonSSHDNotInstalled: true,
	reasonSSHDUnavailable: true, reasonSSHDConfigUnresolved: true,
	reasonSSHDMatchConditional: true, reasonSSHDMatchUnsupported: true,
	reasonRevocationUnresolved: true, reasonPAMBackendUnresolved: true,
	reasonKerberosMappingUnresolv: true, reasonHostbasedConditional: true,
	reasonHostbasedUnassessed: true, reasonSudoUnsupportedSyntax: true,
	reasonSudoHostConditional: true, reasonSudoPolicyUnresolved: true,
	reasonExternalSource: true, reasonPTYSourceAbsent: true,
	reasonPTYSourceUnsupported: true,
}

// External source kinds.
const (
	externalNSSAccounts      = "nss_accounts"
	externalNSSGroups        = "nss_groups"
	externalKeysCommand      = "authorized_keys_command"
	externalPrincipalsComand = "authorized_principals_command"
	externalLDAPSudo         = "ldap_sudo"
	externalKerberos         = "kerberos"
)

// Report is the wire body of POST /api/servers/servers/-/exposure/. Every
// field is metadata: there is no field that can hold a password hash, a key
// blob, an option value outside the allowlist or a raw line.
type Report struct {
	SchemaVersion int                 `json:"schema_version"`
	ObservedAt    string              `json:"observed_at"`
	Hash          string              `json:"hash"`
	Scope         Scope               `json:"scope"`
	Categories    map[string]Coverage `json:"categories"`
	External      []External          `json:"external"`
	SSHD          SSHD                `json:"sshd"`
	UserCA        *UserCA             `json:"user_ca"`
	SystemTrust   []SystemTrustFile   `json:"system_trust"`
	Accounts      []Account           `json:"accounts"`
}

// Scope names what the report inspects.
type Scope struct {
	OS       string `json:"os"`
	Protocol string `json:"protocol"`
}

// Coverage is one category's status and its sorted reason codes.
type Coverage struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// External is one provider the host consults that the report does not
// resolve. Path and User belong to the command kinds and Sources to the NSS
// kinds; the others are null.
type External struct {
	Kind    string   `json:"kind"`
	Scope   string   `json:"scope"`
	Path    *string  `json:"path"`
	User    *string  `json:"user"`
	Sources []string `json:"sources" nullable:"true"`
}

// SSHD is the effective sshd policy. Effective is null when sshd -T could
// not be run; otherwise it holds exactly the effectiveKeywords.
type SSHD struct {
	Effective   map[string]*string `json:"effective"`
	MatchBlocks []MatchBlock       `json:"match_blocks"`
	Daemon      Daemon             `json:"daemon"`
}

// MatchBlock is one Match block in configuration file order.
type MatchBlock struct {
	Criteria *string           `json:"criteria"`
	Sets     map[string]string `json:"sets"`
}

// Daemon says whether the inspected configuration is the one the running
// sshd uses.
type Daemon struct {
	ConfigPathMatches *bool  `json:"config_path_matches"`
	Correspondence    string `json:"correspondence"`
}

// Envelope is the common header of every file-backed source.
type Envelope struct {
	Path     string   `json:"path"`
	Status   string   `json:"status"`
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons"`
}

// KeyFile is one AuthorizedKeysFile source.
type KeyFile struct {
	Envelope
	OwnerUID      *uint32 `json:"owner_uid"`
	Mode          *string `json:"mode"`
	UnparsedLines int     `json:"unparsed_lines"`
	Keys          []Key   `json:"keys"`
}

// Key is one public key, identified by its fingerprint.
type Key struct {
	Fingerprint    string          `json:"fingerprint"`
	Type           string          `json:"type"`
	Bits           int             `json:"bits"`
	Authorizations []Authorization `json:"authorizations"`
}

// Authorization is one distinct permitted-metadata variant of a key.
type Authorization struct {
	Count            int      `json:"count"`
	Role             string   `json:"role"`
	Comment          *string  `json:"comment"`
	CommentTruncated bool     `json:"comment_truncated"`
	Options          []string `json:"options"`
	From             *string  `json:"from"`
	Principals       []string `json:"principals" nullable:"true"`
	ExpiryTime       *string  `json:"expiry_time"`
}

// UserCA is the TrustedUserCAKeys source.
type UserCA struct {
	Envelope
	CAs []CA `json:"cas"`
}

// CA is one trusted user-CA key.
type CA struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
}

// PrincipalsFile is one AuthorizedPrincipalsFile source.
type PrincipalsFile struct {
	Envelope
	Entries []PrincipalEntry `json:"entries"`
}

// PrincipalEntry is one line of a principals file.
type PrincipalEntry struct {
	Principals []string `json:"principals"`
	Options    []string `json:"options"`
	From       *string  `json:"from"`
}

// TrustFile is a .k5login, .rhosts or .shosts file in an account's home.
type TrustFile struct {
	Envelope
	Kind    string       `json:"kind"`
	Entries []TrustEntry `json:"entries"`
}

// SystemTrustFile is /etc/hosts.equiv or /etc/ssh/shosts.equiv.
type SystemTrustFile struct {
	Envelope
	Entries []HostUser `json:"entries"`
}

// TrustEntry is a .k5login principal or a .rhosts/.shosts host-user pair.
type TrustEntry struct {
	Principal *string
	HostUser  *HostUser
}

// MarshalJSON encodes a principal as a string and a host-user pair as an
// object.
func (e TrustEntry) MarshalJSON() ([]byte, error) {
	if e.Principal != nil {
		return appendJSONString(nil, *e.Principal), nil
	}
	if e.HostUser != nil {
		return encodeValue(*e.HostUser)
	}
	return []byte("null"), nil
}

// HostUser is one hosts-equivalence entry.
type HostUser struct {
	Host string  `json:"host"`
	User *string `json:"user"`
}

// Account is one /etc/passwd entry.
type Account struct {
	Username        string           `json:"username"`
	UID             uint32           `json:"uid"`
	Shell           *string          `json:"shell"`
	LoginShell      bool             `json:"login_shell"`
	Groups          []string         `json:"groups"`
	Shadow          Shadow           `json:"shadow"`
	Home            Home             `json:"home"`
	KeyFiles        []KeyFile        `json:"key_files"`
	PrincipalsFiles []PrincipalsFile `json:"principals_files"`
	TrustFiles      []TrustFile      `json:"trust_files"`
	Sudo            AccountSudo      `json:"sudo"`
	LastPTYLogin    *PTYLogin        `json:"last_pty_login"`
}

// Shadow is the account's /etc/shadow state, derived in process. The
// password field's bytes are classified and dropped; no field holds them.
type Shadow struct {
	Status         string `json:"status"`
	PasswordState  string `json:"password_state"`
	LastChangeDays *int64 `json:"last_change_days"`
	ExpireDays     *int64 `json:"expire_days"`
	InactiveDays   *int64 `json:"inactive_days"`
}

// Home is the account's home directory state.
type Home struct {
	Status        string `json:"status"`
	StrictModesOK *bool  `json:"strict_modes_ok"`
}

// AccountSudo is what the readable sudo policy grants the account.
type AccountSudo struct {
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons"`
	Grants   []Grant  `json:"grants"`
}

// Grant is one sudo grant in policy order. Command arguments are never
// carried, only whether the policy restricts them.
type Grant struct {
	Source         string   `json:"source"`
	Via            string   `json:"via"`
	Runas          string   `json:"runas"`
	Commands       string   `json:"commands"` // "all" or "limited"
	CommandPaths   []string `json:"command_paths"`
	ArgsRestricted bool     `json:"args_restricted"`
	NoPasswd       bool     `json:"nopasswd"`
}

// PTYLogin is the account's last PTY login from lastlog or wtmp.
type PTYLogin struct {
	Time   string  `json:"time"`
	Source *string `json:"source"`
	TTY    *string `json:"tty"`
	From   string  `json:"from"`
}

// Password states.
const (
	passwordEmpty   = "empty"
	passwordNone    = "none"
	passwordLocked  = "locked"
	passwordSet     = "set"
	passwordUnknown = "unknown"
)

// Shadow status values.
const (
	shadowRead       = "read"
	shadowUnreadable = "unreadable"
	shadowNoEntry    = "no_entry"
)
