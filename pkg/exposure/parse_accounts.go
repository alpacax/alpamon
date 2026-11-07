package exposure

import (
	"bytes"
	"strconv"
	"strings"
)

type passwdEntry struct {
	name  string
	uid   uint32
	gid   uint32
	home  string // "" when the field is not a usable absolute path
	shell string // "" for an empty shell field
	// passwordInPasswd is set when field 2 is not "x": the password lives in
	// /etc/passwd itself, so the shadow-derived state may not be the one used.
	passwordInPasswd bool
}

type passwdResult struct {
	entries   []passwdEntry
	unparsed  int
	overLimit bool
}

// parsePasswd reads /etc/passwd. Only the first entry for a name counts, as
// for getpwnam; a later duplicate is unparsed. Field 2 is compared with "x"
// and never kept.
func parsePasswd(data []byte) passwdResult {
	var res passwdResult
	seen := map[string]bool{}
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if tooLong {
			res.unparsed++
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		e, ok := parsePasswdLine(line)
		if !ok || seen[e.name] {
			res.unparsed++
			return true
		}
		if len(res.entries) >= maxAccounts {
			res.overLimit = true
			return false
		}
		seen[e.name] = true
		res.entries = append(res.entries, e)
		return true
	})
	return res
}

func parsePasswdLine(line []byte) (passwdEntry, bool) {
	f := bytes.Split(line, []byte(":"))
	if len(f) != 7 {
		return passwdEntry{}, false
	}
	name := string(f[0])
	if !validName(name) {
		return passwdEntry{}, false
	}
	uid, err1 := strconv.ParseUint(string(f[2]), 10, 32)
	gid, err2 := strconv.ParseUint(string(f[3]), 10, 32)
	if err1 != nil || err2 != nil {
		return passwdEntry{}, false
	}
	e := passwdEntry{
		name:             name,
		uid:              uint32(uid),
		gid:              uint32(gid),
		passwordInPasswd: !bytes.Equal(f[1], []byte("x")),
	}
	if home := string(f[5]); home == "/" || validPath(home) {
		e.home = home
	}
	if shell := string(f[6]); shell != "" {
		if !validPath(shell) {
			return passwdEntry{}, false
		}
		e.shell = shell
	}
	return e, true
}

type groupEntry struct {
	name    string
	gid     uint32
	members []string
}

type groupResult struct {
	groups   []groupEntry
	unparsed int
}

func parseGroup(data []byte) groupResult {
	var res groupResult
	seen := map[string]bool{}
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if tooLong {
			res.unparsed++
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		f := bytes.Split(line, []byte(":"))
		if len(f) != 4 || !validName(string(f[0])) || seen[string(f[0])] {
			res.unparsed++
			return true
		}
		gid, err := strconv.ParseUint(string(f[2]), 10, 32)
		if err != nil {
			res.unparsed++
			return true
		}
		g := groupEntry{name: string(f[0]), gid: uint32(gid)}
		if len(f[3]) > 0 {
			for m := range bytes.SplitSeq(f[3], []byte(",")) {
				if !validName(string(m)) {
					res.unparsed++
					continue
				}
				g.members = append(g.members, string(m))
			}
		}
		seen[g.name] = true
		res.groups = append(res.groups, g)
		return true
	})
	return res
}

// parseShells returns the absolute paths listed in /etc/shells.
func parseShells(data []byte) map[string]bool {
	shells := map[string]bool{}
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if tooLong || isBlankOrComment(line) {
			return true
		}
		if s := string(bytes.TrimSpace(line)); validPath(s) {
			shells[s] = true
		}
		return true
	})
	return shells
}

// isNoLoginShell reports a shell that refuses interactive login.
func isNoLoginShell(shell string) bool {
	base := shell[strings.LastIndexByte(shell, '/')+1:]
	return base == "nologin" || base == "false"
}

// parseNSSwitch returns the service modules each database line names, with
// action items such as [NOTFOUND=return] dropped. unparsed counts module
// names outside the name grammar.
func parseNSSwitch(data []byte) (map[string][]string, int) {
	dbs := map[string][]string{}
	unparsed := 0
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if tooLong {
			unparsed++
			return true
		}
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		db, rest, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			if len(bytes.TrimSpace(line)) > 0 {
				unparsed++
			}
			return true
		}
		name := string(bytes.TrimSpace(db))
		var modules []string
		inAction := false
		for _, tok := range strings.Fields(string(rest)) {
			if strings.HasPrefix(tok, "[") {
				inAction = true
			}
			if inAction {
				if strings.HasSuffix(tok, "]") {
					inAction = false
				}
				continue
			}
			if !validName(tok) {
				unparsed++
				continue
			}
			modules = append(modules, tok)
		}
		dbs[name] = modules
		return true
	})
	return dbs, unparsed
}

type shadowInfo struct {
	state      string
	lastChange *int64
	inactive   *int64
	expire     *int64
	parseErr   bool
}

// parseShadow reads /etc/shadow into per-name metadata. The password field
// is classified where it lies and its bytes are not copied anywhere.
func parseShadow(data []byte) (map[string]shadowInfo, int) {
	out := map[string]shadowInfo{}
	unparsed := 0
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if tooLong {
			unparsed++
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		f := bytes.Split(line, []byte(":"))
		if len(f) != 9 || !validName(string(f[0])) {
			unparsed++
			return true
		}
		name := string(f[0])
		if _, dup := out[name]; dup {
			unparsed++
			return true
		}
		info := shadowInfo{state: classifyPassword(f[1])}
		var bad bool
		info.lastChange, bad = shadowDays(f[2])
		info.parseErr = info.parseErr || bad
		info.inactive, bad = shadowDays(f[6])
		info.parseErr = info.parseErr || bad
		info.expire, bad = shadowDays(f[7])
		info.parseErr = info.parseErr || bad
		if info.state == passwordUnknown {
			info.parseErr = true
		}
		out[name] = info
		return true
	})
	return out, unparsed
}

func shadowDays(f []byte) (*int64, bool) {
	if len(f) == 0 {
		return nil, false
	}
	v, err := strconv.ParseInt(string(f), 10, 64)
	if err != nil || v < 0 {
		return nil, true
	}
	return &v, false
}

// classifyPassword derives the password state from shadow field 2.
func classifyPassword(f []byte) string {
	if len(f) == 0 {
		return passwordEmpty
	}
	rest := bytes.TrimLeft(f, "!")
	locked := len(rest) < len(f)
	switch {
	case len(rest) == 0:
		if len(f) <= 2 {
			return passwordNone // "!" or "!!"
		}
		return passwordUnknown
	case len(rest) == 1 && rest[0] == '*':
		if len(f) <= 2 {
			return passwordNone // "*" or "!*"
		}
		return passwordUnknown
	case isCryptHash(rest):
		if locked {
			return passwordLocked
		}
		return passwordSet
	}
	return passwordUnknown
}

func isCryptAlphabet(c byte) bool {
	return isAlnum(c) || c == '.' || c == '/'
}

// isCryptHash recognizes a crypt(3) hash by shape only: $id$..., a
// 13-character DES hash or a 20-character BSDi hash.
func isCryptHash(h []byte) bool {
	switch {
	case len(h) == 13:
		for _, c := range h {
			if !isCryptAlphabet(c) {
				return false
			}
		}
		return true
	case len(h) == 20 && h[0] == '_':
		for _, c := range h[1:] {
			if !isCryptAlphabet(c) {
				return false
			}
		}
		return true
	case len(h) >= 4 && h[0] == '$':
		end := bytes.IndexByte(h[1:], '$')
		if end <= 0 {
			return false
		}
		for _, c := range h[1 : 1+end] {
			if !isAlnum(c) {
				return false
			}
		}
		for _, c := range h[1+end:] {
			if !isCryptAlphabet(c) && c != '$' && c != '=' && c != ',' && c != '+' && c != '-' {
				return false
			}
		}
		return true
	}
	return false
}
