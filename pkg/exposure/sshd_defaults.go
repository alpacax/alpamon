package exposure

// The installed sshd version is unknown when the settings come from configuration.
const (
	caAlgorithms = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
		"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com," +
		"rsa-sha2-512,rsa-sha2-256,ssh-rsa"
	pubkeyAlgorithms = "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
		"sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-mldsa44-ed25519-cert," +
		caAlgorithms + ",ssh-mldsa44-ed25519"
)

var sshdDefaults = map[string]string{
	"passwordauthentication":       "yes",                                        // OpenSSH sshd_config(5), PasswordAuthentication.
	"kbdinteractiveauthentication": "yes",                                        // OpenSSH sshd_config(5), KbdInteractiveAuthentication.
	"usepam":                       "yes",                                        // Debian, Ubuntu and RHEL enable PAM in their shipped configurations.
	"permitemptypasswords":         "no",                                         // OpenSSH sshd_config(5), PermitEmptyPasswords.
	"permitrootlogin":              "prohibit-password",                          // OpenSSH 7.0 and later, PermitRootLogin.
	"pubkeyauthentication":         "yes",                                        // OpenSSH sshd_config(5), PubkeyAuthentication.
	"authenticationmethods":        "any",                                        // OpenSSH sshd_config(5), AuthenticationMethods.
	"pubkeyacceptedalgorithms":     pubkeyAlgorithms,                             // OpenSSH myproposal.h, 7.4p1–10.6p1: RSA/SHA-1, security keys (8.2p1), WebAuthn (10.4p1) and ML-DSA (10.6p1).
	"casignaturealgorithms":        caAlgorithms,                                 // OpenSSH SSH_ALLOWED_CA_SIGALGS, 7.9p1–10.6p1: includes legacy RSA/SHA-1 and newer security-key signatures.
	"authorizedkeysfile":           ".ssh/authorized_keys .ssh/authorized_keys2", // OpenSSH sshd_config(5), AuthorizedKeysFile.
	"authorizedprincipalsfile":     "none",                                       // OpenSSH sshd_config(5), AuthorizedPrincipalsFile.
	"trustedusercakeys":            "none",                                       // OpenSSH sshd_config(5), TrustedUserCAKeys.
	"revokedkeys":                  "none",                                       // OpenSSH sshd_config(5), RevokedKeys.
	"strictmodes":                  "yes",                                        // OpenSSH sshd_config(5), StrictModes.
	"gssapiauthentication":         "no",                                         // OpenSSH sshd_config(5), GSSAPIAuthentication.
	"kerberosauthentication":       "no",                                         // OpenSSH sshd_config(5), KerberosAuthentication.
	"kerberosorlocalpasswd":        "yes",                                        // OpenSSH sshd_config(5), KerberosOrLocalPasswd.
	"hostbasedauthentication":      "no",                                         // OpenSSH sshd_config(5), HostbasedAuthentication.
	"ignorerhosts":                 "yes",                                        // OpenSSH sshd_config(5), IgnoreRhosts.
	"ignoreuserknownhosts":         "no",                                         // OpenSSH sshd_config(5), IgnoreUserKnownHosts.
	"allowusers":                   "",                                           // OpenSSH sshd_config(5), AllowUsers.
	"denyusers":                    "",                                           // OpenSSH sshd_config(5), DenyUsers.
	"allowgroups":                  "",                                           // OpenSSH sshd_config(5), AllowGroups.
	"denygroups":                   "",                                           // OpenSSH sshd_config(5), DenyGroups.
}
