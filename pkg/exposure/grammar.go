package exposure

import (
	"net/netip"
	"strings"
)

// Grammar checks for every string that reaches the report. A value that
// fails its check is never sent; the caller counts it as unparsed instead.

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// validName is a user or group name: a letter, digit, '_' or '.', then the
// same or '-', with an optional trailing '$' for machine accounts.
func validName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlnum(c) || c == '_' || c == '.':
		case c == '-' && i > 0:
		case c == '$' && i == len(s)-1 && i > 0:
		default:
			return false
		}
	}
	return true
}

// validHostname is an RFC 1123 host name or an IP address literal.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !isAlnum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

// validHostPattern is an sshd host pattern: host name characters plus the
// '*' and '?' wildcards.
func validHostPattern(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '-' && c != '.' && c != '*' && c != '?' && c != '_' {
			return false
		}
	}
	return true
}

// validFrom checks a from= value: a comma-separated list whose every element,
// optionally negated with '!', is an address, a CIDR or a host pattern.
func validFrom(s string) bool {
	if s == "" || len(s) > maxFromBytes {
		return false
	}
	for elem := range strings.SplitSeq(s, ",") {
		elem = strings.TrimPrefix(elem, "!")
		if elem == "" {
			return false
		}
		if _, err := netip.ParseAddr(elem); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(elem); err == nil {
			continue
		}
		if !validHostPattern(elem) {
			return false
		}
	}
	return true
}

// validPrincipal is a certificate principal: printable ASCII without space,
// comma, quote or backslash, at most 256 bytes.
func validPrincipal(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c > '~' || c == ',' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// validK5Principal matches ^[^\s@]+(@[^\s@]+)?$ over printable ASCII, at
// most 256 bytes.
func validK5Principal(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	name, realm, hasRealm := strings.Cut(s, "@")
	if name == "" || (hasRealm && realm == "") || strings.Contains(realm, "@") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// validPath is an absolute path of printable ASCII without whitespace,
// quotes or backslashes, with no empty, "." or ".." component.
func validPath(s string) bool {
	if len(s) < 2 || len(s) > 4096 || s[0] != '/' || s[len(s)-1] == '/' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c > '~' || c == '"' || c == '\'' || c == '\\' || c == '`' {
			return false
		}
	}
	for comp := range strings.SplitSeq(s[1:], "/") {
		if comp == "" || comp == "." || comp == ".." || len(comp) > 255 {
			return false
		}
	}
	return true
}

// validTTY is a terminal line such as pts/0 or tty1.
func validTTY(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '/' && c != '.' && c != '_' && c != ':' && c != '-' {
			return false
		}
	}
	return true
}

// validToken is one printable ASCII token of a configuration value.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// validValue is a configuration value: printable ASCII tokens separated by
// single spaces, at most maxEffectiveValueLen bytes.
func validValue(s string) bool {
	if s == "" || len(s) > maxEffectiveValueLen {
		return false
	}
	for tok := range strings.SplitSeq(s, " ") {
		if !validToken(tok) {
			return false
		}
	}
	return true
}
