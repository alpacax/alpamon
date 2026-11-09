package exposure

import (
	"encoding/json"
	"errors"
)

// schemaVersion is the report schema this agent sends.
const schemaVersion = 1

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

// coverage status values.
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
	reasonFileUnreadable            = "file_unreadable"
	reasonFileRejected              = "file_rejected"
	reasonParseError                = "parse_error"
	reasonLimitExceeded             = "limit_exceeded"
	reasonConcurrentChange          = "concurrent_change"
	reasonTimeout                   = "timeout"
	reasonHomeUnreadable            = "home_unreadable"
	reasonPathTokenUnresolved       = "path_token_unresolved"
	reasonStrictModesUnresolved     = "strict_modes_unresolved"
	reasonSSHDNotInstalled          = "sshd_not_installed"
	reasonSSHDUnavailable           = "sshd_unavailable"
	reasonSSHDConfigUnresolved      = "sshd_config_unresolved"
	reasonSSHDMatchConditional      = "sshd_match_conditional"
	reasonSSHDMatchUnsupported      = "sshd_match_unsupported"
	reasonRevocationUnresolved      = "revocation_unresolved"
	reasonPAMBackendUnresolved      = "pam_backend_unresolved"
	reasonKerberosMappingUnresolved = "kerberos_mapping_unresolved"
	reasonHostbasedConditional      = "hostbased_conditional"
	reasonHostbasedUnassessed       = "hostbased_unassessed"
	reasonSudoUnsupportedSyntax     = "sudo_unsupported_syntax"
	reasonSudoHostConditional       = "sudo_host_conditional"
	reasonSudoPolicyUnresolved      = "sudo_policy_unresolved"
	reasonExternalSource            = "external_source"
	reasonPTYSourceAbsent           = "pty_source_absent"
	reasonPTYSourceUnsupported      = "pty_source_unsupported"
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
	reasonKerberosMappingUnresolved: true, reasonHostbasedConditional: true,
	reasonHostbasedUnassessed: true, reasonSudoUnsupportedSyntax: true,
	reasonSudoHostConditional: true, reasonSudoPolicyUnresolved: true,
	reasonExternalSource: true, reasonPTYSourceAbsent: true,
	reasonPTYSourceUnsupported: true,
}

// external source kinds.
const (
	externalNSSAccounts       = "nss_accounts"
	externalNSSGroups         = "nss_groups"
	externalKeysCommand       = "authorized_keys_command"
	externalPrincipalsCommand = "authorized_principals_command"
	externalLDAPSudo          = "ldap_sudo"
	externalKerberos          = "kerberos"
)

// exposureReport is the wire body of POST /api/servers/servers/-/exposure/. Every
// field is metadata: there is no field that can hold a password hash, a key
// blob, an option value outside the allowlist or a raw line.
type exposureReport struct {
	SchemaVersion int                 `json:"schema_version"`
	ObservedAt    string              `json:"observed_at"`
	Hash          string              `json:"hash"`
	Scope         reportScope         `json:"scope"`
	Categories    map[string]coverage `json:"categories"`
	External      []external          `json:"external"`
	SSHD          sshdPolicy          `json:"sshd"`
	UserCA        *userCA             `json:"user_ca"`
	SystemTrust   []systemTrustFile   `json:"system_trust"`
	Accounts      []account           `json:"accounts"`
}

// reportScope names what the report inspects.
type reportScope struct {
	OS       string `json:"os"`
	Protocol string `json:"protocol"`
}

// coverage is one category's status and its sorted reason codes.
type coverage struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// external is one provider the host consults that the report does not
// resolve. Path and User belong to the command kinds and Sources to the NSS
// kinds; the others are null.
type external struct {
	Kind    string   `json:"kind"`
	Scope   string   `json:"scope"`
	Path    *string  `json:"path"`
	User    *string  `json:"user"`
	Sources []string `json:"sources" nullable:"true"`
}

// sshdPolicy is the effective sshd policy. Effective is null when sshd -T could
// not be run; otherwise it holds exactly the effectiveKeywords.
type sshdPolicy struct {
	Effective   map[string]*string `json:"effective"`
	MatchBlocks []matchSettings    `json:"match_blocks"`
	Daemon      daemon             `json:"daemon"`
}

// matchSettings is one Match block in configuration file order.
type matchSettings struct {
	Criteria *string           `json:"criteria"`
	Sets     map[string]string `json:"sets"`
}

// daemon says whether the inspected configuration is the one the running
// sshd uses.
type daemon struct {
	ConfigPathMatches *bool  `json:"config_path_matches"`
	Correspondence    string `json:"correspondence"`
}

// envelope is the common header of every file-backed source.
type envelope struct {
	Path     string   `json:"path"`
	Status   string   `json:"status"`
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons"`
}

// keyFile is one AuthorizedKeysFile source.
type keyFile struct {
	envelope
	OwnerUID      *uint32 `json:"owner_uid"`
	Mode          *string `json:"mode"`
	UnparsedLines int     `json:"unparsed_lines"`
	Keys          []key   `json:"keys"`
}

// key is one public key, identified by its fingerprint.
type key struct {
	Fingerprint    string          `json:"fingerprint"`
	Type           string          `json:"type"`
	Bits           int             `json:"bits"`
	Authorizations []authorization `json:"authorizations"`
}

// authorization is one distinct permitted-metadata variant of a key.
type authorization struct {
	Count            int      `json:"count"`
	Role             string   `json:"role"`
	Comment          *string  `json:"comment"`
	CommentTruncated bool     `json:"comment_truncated"`
	Options          []string `json:"options"`
	From             *string  `json:"from"`
	Principals       []string `json:"principals" nullable:"true"`
	ExpiryTime       *string  `json:"expiry_time"`
}

// userCA is the TrustedUserCAKeys source.
type userCA struct {
	envelope
	CAs []caKey `json:"cas"`
}

// caKey is one trusted user-CA key.
type caKey struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
}

// principalsFile is one AuthorizedPrincipalsFile source.
type principalsFile struct {
	envelope
	Entries []principalEntry `json:"entries"`
}

// principalEntry is one line of a principals file.
type principalEntry struct {
	Principals []string `json:"principals"`
	Options    []string `json:"options"`
	From       *string  `json:"from"`
}

// trustFile is a .k5login, .rhosts or .shosts file in an account's home.
type trustFile struct {
	envelope
	Kind    string       `json:"kind"`
	Entries []trustEntry `json:"entries"`
}

// systemTrustFile is /etc/hosts.equiv or /etc/ssh/shosts.equiv.
type systemTrustFile struct {
	envelope
	Entries []hostUser `json:"entries"`
}

// trustEntry is a .k5login principal or a .rhosts/.shosts host-user pair.
type trustEntry struct {
	Principal *string
	HostUser  *hostUser
}

// MarshalJSON encodes a principal as a string and a host-user pair as an
// object.
func (e trustEntry) MarshalJSON() ([]byte, error) {
	if e.Principal != nil {
		return appendJSONString(nil, *e.Principal), nil
	}
	if e.HostUser != nil {
		return encodeValue(*e.HostUser)
	}
	return nil, errors.New("invalid trust entry")
}

// UnmarshalJSON accepts a principal string or a host-user object.
func (e *trustEntry) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("invalid trust entry")
	}
	switch v := value.(type) {
	case string:
		*e = trustEntry{Principal: &v}
		return nil
	case map[string]any:
		host, ok := v["host"].(string)
		user, hasUser := v["user"]
		if !ok || !hasUser || len(v) != 2 {
			break
		}
		pair := hostUser{Host: host}
		switch u := user.(type) {
		case nil:
		case string:
			pair.User = &u
		default:
			return errors.New("invalid trust entry")
		}
		*e = trustEntry{HostUser: &pair}
		return nil
	}
	return errors.New("invalid trust entry")
}

// hostUser is one hosts-equivalence entry.
type hostUser struct {
	Host string  `json:"host"`
	User *string `json:"user"`
}

// account is one /etc/passwd entry.
type account struct {
	Username        string           `json:"username"`
	UID             uint32           `json:"uid"`
	Shell           *string          `json:"shell"`
	LoginShell      bool             `json:"login_shell"`
	Groups          []string         `json:"groups"`
	Shadow          shadow           `json:"shadow"`
	Home            home             `json:"home"`
	KeyFiles        []keyFile        `json:"key_files"`
	PrincipalsFiles []principalsFile `json:"principals_files"`
	TrustFiles      []trustFile      `json:"trust_files"`
	Sudo            accountSudo      `json:"sudo"`
	LastPTYLogin    *ptyLogin        `json:"last_pty_login"`
}

// shadow is the account's /etc/shadow state, derived in process. The
// password field's bytes are classified and dropped; no field holds them.
type shadow struct {
	Status         string `json:"status"`
	PasswordState  string `json:"password_state"`
	LastChangeDays *int64 `json:"last_change_days"`
	ExpireDays     *int64 `json:"expire_days"`
	InactiveDays   *int64 `json:"inactive_days"`
}

// home is the account's home directory state.
type home struct {
	Status        string `json:"status"`
	StrictModesOK *bool  `json:"strict_modes_ok"`
}

// accountSudo is what the readable sudo policy grants the account.
type accountSudo struct {
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons"`
	Grants   []grant  `json:"grants"`
}

// grant is one sudo grant in policy order. Command arguments are never
// carried, only whether the policy restricts them.
type grant struct {
	Source         string   `json:"source"`
	Via            string   `json:"via"`
	Runas          string   `json:"runas"`
	Commands       string   `json:"commands"` // "all" or "limited"
	CommandPaths   []string `json:"command_paths"`
	ArgsRestricted bool     `json:"args_restricted"`
	NoPasswd       bool     `json:"nopasswd"`
}

// ptyLogin is the account's last PTY login from lastlog or wtmp.
type ptyLogin struct {
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

// shadow status values.
const (
	shadowRead       = "read"
	shadowUnreadable = "unreadable"
	shadowNoEntry    = "no_entry"
)
