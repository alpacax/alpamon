package exposure

import (
	"bytes"
	"cmp"
	"slices"
	"strings"
)

// parseK5Login returns the principals of a .k5login file.
func parseK5Login(data []byte) ([]TrustEntry, int, bool) {
	var out []TrustEntry
	seen := map[string]bool{}
	unparsed, tooLong := 0, false
	forEachLine(data, func(line []byte, long bool) bool {
		if long {
			tooLong = true
			return true
		}
		s := string(bytes.TrimSpace(line))
		if s == "" {
			return true
		}
		if !validK5Principal(s) {
			unparsed++
			return true
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, TrustEntry{Principal: &s})
		}
		return true
	})
	slices.SortFunc(out, func(a, b TrustEntry) int { return strings.Compare(*a.Principal, *b.Principal) })
	return out, unparsed, tooLong
}

// parseHostsEquiv returns the host-user pairs of a .rhosts, .shosts,
// hosts.equiv or shosts.equiv file. Wildcards (+), negation (-) and netgroups
// (@) are outside the grammar and make the line unparsed.
func parseHostsEquiv(data []byte) ([]HostUser, int, bool) {
	var out []HostUser
	seen := map[string]bool{}
	unparsed, tooLong := 0, false
	forEachLine(data, func(line []byte, long bool) bool {
		if long {
			tooLong = true
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		f := strings.Fields(string(line))
		if len(f) > 2 || !validHostname(f[0]) {
			unparsed++
			return true
		}
		hu := HostUser{Host: f[0]}
		if len(f) == 2 {
			if !validName(f[1]) {
				unparsed++
				return true
			}
			hu.User = &f[1]
		}
		key := hu.Host + "\x00"
		if hu.User != nil {
			key += *hu.User
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, hu)
		}
		return true
	})
	slices.SortFunc(out, func(a, b HostUser) int {
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return cmp.Compare(deref(a.User), deref(b.User))
	})
	return out, unparsed, tooLong
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func hostUserEntries(hu []HostUser) []TrustEntry {
	out := make([]TrustEntry, 0, len(hu))
	for i := range hu {
		out = append(out, TrustEntry{HostUser: &hu[i]})
	}
	return out
}

// krb5MappingRelations change where or how a principal maps to an account,
// so .k5login in the home is no longer the whole story.
var krb5MappingRelations = []string{"k5login_directory", "auth_to_local", "auth_to_local_names", "include", "includedir", "module"}

// krb5MappingUnresolved reports whether krb5.conf configures a non-default
// k5login location or mapping, or pulls in files this read does not follow.
func krb5MappingUnresolved(data []byte) bool {
	found := false
	forEachLine(data, func(line []byte, long bool) bool {
		if long {
			found = true
			return false
		}
		s := strings.TrimSpace(string(line))
		if s == "" || s[0] == '#' || s[0] == ';' {
			return true
		}
		words := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
		if len(words) > 0 && slices.Contains(krb5MappingRelations, strings.ToLower(words[0])) {
			found = true
			return false
		}
		return true
	})
	return found
}
