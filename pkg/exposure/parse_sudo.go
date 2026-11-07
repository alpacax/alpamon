package exposure

import (
	"path"
	"slices"
	"strings"
)

// The sudoers reader below supports a closed subset of the grammar and marks
// everything else incomplete. It reads files; it never runs sudo, sudo-rs,
// visudo or cvtsudoers.

const (
	sudoConfPath    = "/etc/sudo.conf"
	sudoersPath     = "/etc/sudoers"
	sudoersRSPath   = "/etc/sudoers-rs"
	sudoersPolicySy = "sudoers_policy"
)

// sudoPolicy is the parsed policy, before it is mapped onto accounts.
type sudoPolicy struct {
	// unresolved means the policy plugin or file could not be determined.
	unresolved bool
	// global reasons make every account's sudo incomplete.
	global reasonSet
	// userReasons are reasons for the accounts a resolvable user list names.
	userReasons []scopedReason
	rules       []sudoRule
}

type scopedReason struct {
	users  []sudoUser
	reason string
}

type sudoUser struct {
	group bool
	name  string
}

func (u sudoUser) via() string {
	if u.group {
		return "group:" + u.name
	}
	return "user:" + u.name
}

type sudoRule struct {
	source      string
	users       []sudoUser
	unsupported bool
	hosts       []sudoHostGroup
}

type sudoHostGroup struct {
	applies     bool
	conditional bool
	grants      []grantTemplate
	overPaths   bool
}

type grantTemplate struct {
	runas          string
	all            bool
	paths          []string
	argsRestricted bool
	nopasswd       bool
}

// sudoAuthDefaults are Defaults settings that change who authenticates or
// how rules match, so the grants read from the rules no longer tell the
// whole story.
var sudoAuthDefaults = map[string]bool{
	"authenticate": true, "rootpw": true, "runaspw": true, "targetpw": true,
	"timestamp_timeout": true, "timestamp_type": true, "runas_default": true,
	"pam_service": true, "pam_login_service": true, "group_plugin": true,
	"fqdn": true, "match_group_by_gid": true,
}

var sudoTags = map[string]bool{
	"NOPASSWD": true, "PASSWD": true, "NOEXEC": true, "EXEC": true,
	"SETENV": true, "NOSETENV": true, "LOG_INPUT": true, "NOLOG_INPUT": true,
	"LOG_OUTPUT": true, "NOLOG_OUTPUT": true, "MAIL": true, "NOMAIL": true,
	"FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true,
}

var sudoCmndOptions = map[string]bool{
	"ROLE": true, "TYPE": true, "CWD": true, "CHROOT": true, "NOTBEFORE": true,
	"NOTAFTER": true, "TIMEOUT": true, "APPARMOR_PROFILE": true, "PRIVS": true,
	"LIMITPRIVS": true,
}

var sudoDigests = map[string]bool{"sha224": true, "sha256": true, "sha384": true, "sha512": true}

// readSudoPolicy reads sudo.conf, the sudoers file it names and every
// include. hostname is the host's own name for host-list matching.
func readSudoPolicy(src systemSource, hostname string) sudoPolicy {
	pol := sudoPolicy{global: reasonSet{}}
	file, ok := sudoersFileFromConf(src)
	if !ok {
		pol.unresolved = true
		return pol
	}
	if rs := src.load(sudoersRSPath); rs.status != statusAbsent {
		// sudo-rs prefers this file when it exists; which binary answers to
		// "sudo" is not something a file read can settle.
		pol.unresolved = true
		return pol
	}
	r := &sudoReader{src: src, pol: &pol, host: hostname, onStack: map[string]bool{},
		userAliases: map[string][]sudoWord{}, hostAliases: map[string][]sudoWord{},
		runasAliases: map[string][]sudoWord{}, cmndAliases: map[string][][]sudoWord{}}
	r.file(file, 0, true)
	r.resolve()
	return pol
}

func sudoersFileFromConf(src systemSource) (string, bool) {
	l := src.load(sudoConfPath)
	if l.status == statusAbsent {
		return sudoersPath, true
	}
	if !l.usable() {
		return "", false
	}
	file, ok := sudoersPath, true
	forEachLine(l.data, func(line []byte, tooLong bool) bool {
		if tooLong {
			ok = false
			return false
		}
		if isBlankOrComment(line) {
			return true
		}
		f := strings.Fields(string(line))
		if len(f) < 3 || f[0] != "Plugin" {
			return true
		}
		switch {
		case f[1] == sudoersPolicySy:
			for _, a := range f[3:] {
				if v, has := strings.CutPrefix(a, "sudoers_file="); has {
					if !validPath(v) {
						ok = false
					}
					file = v
				}
			}
		case strings.HasSuffix(f[1], "_policy"):
			ok = false
		}
		return true
	})
	return file, ok
}

// sudoLine is one logical line with the file it came from.
type sudoLine struct {
	source string
	text   string
}

type sudoReader struct {
	src          systemSource
	pol          *sudoPolicy
	host         string
	onStack      map[string]bool
	nfiles       int
	lines        []sudoLine
	userAliases  map[string][]sudoWord
	hostAliases  map[string][]sudoWord
	runasAliases map[string][]sudoWord
	cmndAliases  map[string][][]sudoWord
}

func (r *sudoReader) file(name string, depth int, top bool) {
	if depth > maxIncludeDepth || r.nfiles >= maxIncludeFiles {
		r.pol.global.add(reasonLimitExceeded)
		return
	}
	if r.onStack[name] {
		r.pol.global.add(reasonParseError)
		return
	}
	r.nfiles++
	l := r.src.load(name)
	if l.status == statusAbsent && top {
		return // no sudoers file: sudo grants nothing
	}
	if !l.usable() {
		r.pol.global.merge(l.reasons)
		if len(l.reasons) == 0 || l.status == statusAbsent {
			r.pol.global.add(reasonFileUnreadable)
		}
		return
	}
	r.onStack[name] = true
	defer delete(r.onStack, name)

	var logical strings.Builder
	forEachLine(l.data, func(raw []byte, tooLong bool) bool {
		if tooLong {
			r.pol.global.add(reasonLimitExceeded)
			logical.Reset()
			return true
		}
		s := string(raw)
		if cont := trailingBackslashes(s); cont%2 == 1 {
			logical.WriteString(s[:len(s)-1])
			if logical.Len() > maxLineBytes {
				r.pol.global.add(reasonLimitExceeded)
				logical.Reset()
			}
			return true
		}
		logical.WriteString(s)
		text := logical.String()
		logical.Reset()
		r.line(name, text, depth)
		return true
	})
	if logical.Len() > 0 {
		r.line(name, logical.String(), depth)
	}
}

func trailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
}

func (r *sudoReader) line(source, text string, depth int) {
	t := strings.TrimSpace(text)
	if t == "" {
		return
	}
	for _, d := range []string{"@includedir", "#includedir", "@include", "#include"} {
		rest, ok := strings.CutPrefix(t, d)
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		arg := strings.TrimSpace(rest)
		if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
			arg = arg[1 : len(arg)-1]
		}
		if !strings.HasPrefix(arg, "/") {
			arg = path.Dir(source) + "/" + arg
		}
		if strings.Contains(arg, "%") || !validPath(arg) {
			r.pol.global.add(reasonParseError)
			return
		}
		if strings.HasSuffix(d, "dir") {
			r.includeDir(arg, depth)
		} else {
			r.file(arg, depth+1, false)
		}
		return
	}
	if t[0] == '#' && (len(t) == 1 || t[1] < '0' || t[1] > '9') {
		return // a comment line
	}
	r.lines = append(r.lines, sudoLine{source: source, text: t})
}

func (r *sudoReader) includeDir(dir string, depth int) {
	names, l := r.src.list(dir)
	if l.status == statusAbsent {
		return
	}
	if l.status != statusRead {
		r.pol.global.merge(l.reasons)
		return
	}
	var keep []string
	for _, n := range names {
		if strings.HasSuffix(n, "~") || strings.Contains(n, ".") {
			continue
		}
		keep = append(keep, n)
	}
	slices.Sort(keep)
	for _, n := range keep {
		r.file(dir+"/"+n, depth+1, false)
	}
}

// Tokens of the subset grammar.
type sudoTok int

const (
	tWord sudoTok = iota
	tComma
	tEq
	tColon
	tLParen
	tRParen
	tNot
)

type sudoWord struct {
	kind    sudoTok
	text    string
	escaped bool // the word held a backslash escape
	quoted  bool
}

// tokenizeSudo splits a logical line. A '#' at the start of a token begins a
// comment unless a digit follows, as sudo reads it.
func tokenizeSudo(s string) ([]sudoWord, bool) {
	var out []sudoWord
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '#' && (i+1 >= len(s) || s[i+1] < '0' || s[i+1] > '9'):
			return out, true
		case c == ',':
			out = append(out, sudoWord{kind: tComma})
			i++
		case c == '=':
			out = append(out, sudoWord{kind: tEq})
			i++
		case c == ':':
			out = append(out, sudoWord{kind: tColon})
			i++
		case c == '(':
			out = append(out, sudoWord{kind: tLParen})
			i++
		case c == ')':
			out = append(out, sudoWord{kind: tRParen})
			i++
		case c == '!':
			out = append(out, sudoWord{kind: tNot})
			i++
		case c == '"':
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				return nil, false
			}
			out = append(out, sudoWord{kind: tWord, text: s[i+1 : i+1+end], quoted: true})
			i += end + 2
		default:
			var b strings.Builder
			w := sudoWord{kind: tWord}
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					w.escaped = true
					i += 2
					continue
				}
				if strings.IndexByte(" \t,=:()!\"", c) >= 0 {
					break
				}
				b.WriteByte(c)
				i++
			}
			w.text = b.String()
			out = append(out, w)
		}
	}
	return out, true
}

func isAliasName(s string) bool {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return s != "ALL"
}

// resolve parses every collected line once all aliases are known, so an
// alias may be used before the line that defines it, as in sudo.
func (r *sudoReader) resolve() {
	var specs []sudoLine
	for _, ln := range r.lines {
		word, _, _ := strings.Cut(ln.text, " ")
		switch {
		case strings.HasPrefix(ln.text, "Defaults"):
			specs = append(specs, ln)
		case word == "User_Alias" || word == "Runas_Alias" || word == "Host_Alias" || word == "Cmnd_Alias" || word == "Cmd_Alias":
			r.alias(word, ln.text[len(word):])
		default:
			specs = append(specs, ln)
		}
	}
	for _, ln := range specs {
		if strings.HasPrefix(ln.text, "Defaults") {
			r.defaults(ln.text)
			continue
		}
		r.spec(ln)
	}
}

func (r *sudoReader) alias(kind, rest string) {
	toks, ok := tokenizeSudo(rest)
	if !ok {
		r.pol.global.add(reasonParseError)
		return
	}
	// NAME = items [: NAME = items]...
	for len(toks) > 0 {
		if len(toks) < 2 || toks[0].kind != tWord || !isAliasName(toks[0].text) || toks[1].kind != tEq {
			r.pol.global.add(reasonParseError)
			return
		}
		name := toks[0].text
		toks = toks[2:]
		end := len(toks)
		for i, t := range toks {
			if t.kind == tColon && i+2 < len(toks) && toks[i+1].kind == tWord && isAliasName(toks[i+1].text) && toks[i+2].kind == tEq {
				end = i
				break
			}
		}
		items := toks[:end]
		if end < len(toks) {
			toks = toks[end+1:]
		} else {
			toks = nil
		}
		switch kind {
		case "User_Alias":
			r.userAliases[name] = items
			// An alias whose members cannot be resolved hides which accounts
			// it covers: every account is incomplete.
			if _, ok := r.users(items, map[string]bool{}); !ok {
				r.pol.global.add(reasonSudoUnsupportedSyntax)
			}
		case "Host_Alias":
			r.hostAliases[name] = items
		case "Runas_Alias":
			r.runasAliases[name] = items
		default:
			r.cmndAliases[name] = splitOnComma(items)
		}
	}
}

func splitOnComma(toks []sudoWord) [][]sudoWord {
	var out [][]sudoWord
	start := 0
	for i, t := range toks {
		if t.kind == tComma {
			out = append(out, toks[start:i])
			start = i + 1
		}
	}
	return append(out, toks[start:])
}

// users resolves a user list. ok is false when any member is outside the
// supported grammar, which means the affected accounts cannot be named.
func (r *sudoReader) users(toks []sudoWord, seen map[string]bool) ([]sudoUser, bool) {
	var out []sudoUser
	for _, item := range splitOnComma(toks) {
		if len(item) != 1 || item[0].kind != tWord || item[0].escaped || item[0].quoted {
			return nil, false
		}
		w := item[0].text
		switch {
		case strings.HasPrefix(w, "%"):
			if !validName(w[1:]) {
				return nil, false
			}
			out = append(out, sudoUser{group: true, name: w[1:]})
		case isAliasName(w) && r.userAliases[w] != nil:
			if seen[w] {
				return nil, false
			}
			seen[w] = true
			sub, ok := r.users(r.userAliases[w], seen)
			if !ok {
				return nil, false
			}
			out = append(out, sub...)
		case validName(w) && w != "ALL":
			out = append(out, sudoUser{name: w})
		default:
			return nil, false
		}
	}
	return out, len(out) > 0
}

func (r *sudoReader) defaults(text string) {
	rest := text[len("Defaults"):]
	binding := byte(0)
	var bindTo string
	if rest != "" && strings.IndexByte("@:!>", rest[0]) >= 0 {
		binding = rest[0]
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			r.pol.global.add(reasonParseError)
			return
		}
		bindTo, rest = rest[1:end], rest[end:]
	} else if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		r.pol.global.add(reasonParseError)
		return
	}
	toks, ok := tokenizeSudo(rest)
	if !ok {
		r.pol.global.add(reasonParseError)
		return
	}
	changesAuth := false
	for _, setting := range splitOnComma(toks) {
		if len(setting) > 0 && setting[0].kind == tNot {
			setting = setting[1:]
		}
		if len(setting) == 0 || setting[0].kind != tWord {
			r.pol.global.add(reasonParseError)
			return
		}
		name, _, _ := strings.Cut(setting[0].text, "+")
		name, _, _ = strings.Cut(name, "-")
		if sudoAuthDefaults[name] {
			changesAuth = true
		}
	}
	if !changesAuth {
		return
	}
	if binding == ':' {
		bt, ok := tokenizeSudo(bindTo)
		if ok {
			if us, ok := r.users(bt, map[string]bool{}); ok {
				r.pol.userReasons = append(r.pol.userReasons, scopedReason{users: us, reason: reasonSudoUnsupportedSyntax})
				return
			}
		}
	}
	r.pol.global.add(reasonSudoUnsupportedSyntax)
}

func (r *sudoReader) spec(ln sudoLine) {
	toks, ok := tokenizeSudo(ln.text)
	if !ok {
		r.pol.global.add(reasonParseError)
		return
	}
	// The user list ends at the first word not preceded by a comma.
	i := 0
	for i < len(toks) {
		if toks[i].kind == tNot {
			i++
			continue
		}
		if toks[i].kind != tWord {
			break
		}
		i++
		if i < len(toks) && toks[i].kind == tComma {
			i++
			continue
		}
		break
	}
	users, usersOK := r.users(toks[:i], map[string]bool{})
	rule := sudoRule{source: ln.source, users: users}
	if !usersOK {
		// Which accounts the rule covers is unknown: every account is
		// incomplete and the rule grants nothing.
		r.pol.global.add(reasonSudoUnsupportedSyntax)
		return
	}
	groups, ok := splitHostGroups(toks[i:])
	if !ok {
		rule.unsupported = true
		r.pol.rules = append(r.pol.rules, rule)
		return
	}
	for _, g := range groups {
		hg, ok := r.hostGroup(g)
		if !ok {
			rule.unsupported = true
			rule.hosts = nil
			break
		}
		rule.hosts = append(rule.hosts, hg)
	}
	r.pol.rules = append(r.pol.rules, rule)
}

type hostGroupToks struct {
	hosts []sudoWord
	cmnds []sudoWord
}

// splitHostGroups splits "hosts = cmnds [: hosts = cmnds]...". A ':' starts a
// new group only when a host list and '=' follow it; tags and runas colons
// stay with their command.
func splitHostGroups(toks []sudoWord) ([]hostGroupToks, bool) {
	var out []hostGroupToks
	for len(toks) > 0 {
		eq := -1
		for i, t := range toks {
			if t.kind == tEq {
				eq = i
				break
			}
			if t.kind != tWord && t.kind != tComma && t.kind != tNot {
				return nil, false
			}
		}
		if eq <= 0 {
			return nil, false
		}
		g := hostGroupToks{hosts: toks[:eq]}
		rest := toks[eq+1:]
		end := len(rest)
		depth := 0
		for i := 0; i < len(rest); i++ {
			switch rest[i].kind {
			case tLParen:
				depth++
			case tRParen:
				depth--
			case tColon:
				if depth != 0 || (i > 0 && rest[i-1].kind == tWord && (sudoTags[rest[i-1].text] || sudoDigests[rest[i-1].text])) {
					continue
				}
				if nextIsHostGroup(rest[i+1:]) {
					end = i
					i = len(rest)
				}
			}
		}
		g.cmnds = rest[:end]
		out = append(out, g)
		if end < len(rest) {
			toks = rest[end+1:]
		} else {
			toks = nil
		}
	}
	return out, true
}

func nextIsHostGroup(toks []sudoWord) bool {
	for _, t := range toks {
		switch t.kind {
		case tEq:
			return true
		case tWord, tComma, tNot:
			continue
		default:
			return false
		}
	}
	return false
}

func (r *sudoReader) hostGroup(g hostGroupToks) (sudoHostGroup, bool) {
	var hg sudoHostGroup
	applies, conditional, ok := r.hosts(g.hosts, map[string]bool{})
	if !ok {
		return hg, false
	}
	hg.applies, hg.conditional = applies, conditional && !applies
	grants, over, ok := r.cmnds(g.cmnds)
	if !ok {
		return hg, false
	}
	hg.grants, hg.overPaths = grants, over
	return hg, true
}

func (r *sudoReader) hostMatches(name string) bool {
	if r.host == "" {
		return false
	}
	short, _, _ := strings.Cut(r.host, ".")
	return strings.EqualFold(name, r.host) || strings.EqualFold(name, short)
}

func (r *sudoReader) hosts(toks []sudoWord, seen map[string]bool) (applies, conditional, ok bool) {
	for _, item := range splitOnComma(toks) {
		if len(item) != 1 || item[0].kind != tWord || item[0].escaped || item[0].quoted {
			return false, false, false
		}
		w := item[0].text
		switch {
		case w == "ALL":
			applies = true
		case isAliasName(w) && r.hostAliases[w] != nil:
			if seen[w] {
				return false, false, false
			}
			seen[w] = true
			a, c, ok := r.hosts(r.hostAliases[w], seen)
			if !ok {
				return false, false, false
			}
			applies, conditional = applies || a, conditional || c
		case strings.HasPrefix(w, "+") || isAliasName(w):
			// A netgroup or an undefined alias: not resolvable here.
			return false, false, false
		case r.hostMatches(w):
			applies = true
		default:
			// Another host name or an address this host may answer to.
			conditional = true
		}
	}
	return applies, conditional, true
}

func (r *sudoReader) runas(toks []sudoWord) (string, bool) {
	userToks, groupToks := toks, []sudoWord(nil)
	hasGroups := false
	for i, t := range toks {
		if t.kind == tColon {
			userToks, groupToks, hasGroups = toks[:i], toks[i+1:], true
			break
		}
	}
	users, ok := r.runasList(userToks, map[string]bool{})
	if !ok {
		return "", false
	}
	out := strings.Join(users, ",")
	if hasGroups {
		groups, ok := r.runasList(groupToks, map[string]bool{})
		if !ok {
			return "", false
		}
		out += ":" + strings.Join(groups, ",")
	}
	return out, true
}

func (r *sudoReader) runasList(toks []sudoWord, seen map[string]bool) ([]string, bool) {
	if len(toks) == 0 {
		return nil, true
	}
	var out []string
	for _, item := range splitOnComma(toks) {
		if len(item) != 1 || item[0].kind != tWord || item[0].escaped || item[0].quoted {
			return nil, false
		}
		w := item[0].text
		switch {
		case w == "ALL":
			out = append(out, w)
		case isAliasName(w) && r.runasAliases[w] != nil:
			if seen[w] {
				return nil, false
			}
			seen[w] = true
			sub, ok := r.runasList(r.runasAliases[w], seen)
			if !ok {
				return nil, false
			}
			out = append(out, sub...)
		case strings.HasPrefix(w, "%") && validName(w[1:]):
			out = append(out, w)
		case validName(w) && !isAliasName(w):
			out = append(out, w)
		default:
			return nil, false
		}
	}
	return out, true
}

// cmndItem is one resolved command: ALL or an absolute path, with whether
// arguments follow it. The arguments are not kept.
type cmndItem struct {
	all            bool
	path           string
	argsRestricted bool
}

// cmnds parses a command spec list into grants, merging consecutive commands
// that share runas and the NOPASSWD state.
func (r *sudoReader) cmnds(toks []sudoWord) ([]grantTemplate, bool, bool) {
	var grants []grantTemplate
	runas := "root"
	nopasswd := false
	over := false
	for _, spec := range splitCmndSpecs(toks) {
		if len(spec) > 0 && spec[0].kind == tLParen {
			end := -1
			for i, t := range spec {
				if t.kind == tRParen {
					end = i
					break
				}
			}
			if end < 0 {
				return nil, false, false
			}
			ra, ok := r.runas(spec[1:end])
			if !ok {
				return nil, false, false
			}
			runas, spec = ra, spec[end+1:]
		}
		if len(spec) >= 2 && spec[0].kind == tWord && spec[1].kind == tEq && sudoCmndOptions[spec[0].text] {
			return nil, false, false
		}
		for len(spec) >= 2 && spec[0].kind == tWord && spec[1].kind == tColon && sudoTags[spec[0].text] {
			switch spec[0].text {
			case "NOPASSWD":
				nopasswd = true
			case "PASSWD":
				nopasswd = false
			}
			spec = spec[2:]
		}
		items, ok := r.cmnd(spec, map[string]bool{})
		if !ok {
			return nil, false, false
		}
		for _, it := range items {
			var g *grantTemplate
			if n := len(grants); n > 0 && grants[n-1].runas == runas && grants[n-1].nopasswd == nopasswd {
				g = &grants[n-1]
			} else {
				grants = append(grants, grantTemplate{runas: runas, nopasswd: nopasswd})
				g = &grants[len(grants)-1]
			}
			switch {
			case it.all:
				g.all, g.paths, g.argsRestricted = true, nil, false
			case g.all:
			default:
				if !slices.Contains(g.paths, it.path) {
					if len(g.paths) >= maxCommandPaths {
						over = true
					} else {
						g.paths = append(g.paths, it.path)
					}
				}
				g.argsRestricted = g.argsRestricted || it.argsRestricted
			}
		}
	}
	return grants, over, len(grants) > 0
}

// splitCmndSpecs splits on commas outside parentheses.
func splitCmndSpecs(toks []sudoWord) [][]sudoWord {
	var out [][]sudoWord
	start, depth := 0, 0
	for i, t := range toks {
		switch t.kind {
		case tLParen:
			depth++
		case tRParen:
			depth--
		case tComma:
			if depth == 0 {
				out = append(out, toks[start:i])
				start = i + 1
			}
		}
	}
	return append(out, toks[start:])
}

func (r *sudoReader) cmnd(spec []sudoWord, seen map[string]bool) ([]cmndItem, bool) {
	if len(spec) == 0 || spec[0].kind != tWord {
		// Empty, negated ("!"), or not a word: outside the supported grammar.
		return nil, false
	}
	w := spec[0]
	if w.escaped || w.quoted {
		return nil, false
	}
	if sudoDigests[w.text] {
		return nil, false
	}
	args := spec[1:]
	for _, a := range args {
		if a.kind != tWord {
			return nil, false
		}
	}
	switch {
	case w.text == "ALL":
		if len(args) > 0 {
			return nil, false
		}
		return []cmndItem{{all: true}}, true
	case isAliasName(w.text):
		alias, ok := r.cmndAliases[w.text]
		if !ok || len(args) > 0 || seen[w.text] {
			return nil, false
		}
		seen[w.text] = true
		var out []cmndItem
		for _, item := range alias {
			sub, ok := r.cmnd(item, seen)
			if !ok {
				return nil, false
			}
			out = append(out, sub...)
		}
		return out, true
	case validPath(w.text) && !hasGlob(w.text):
		return []cmndItem{{path: w.text, argsRestricted: len(args) > 0}}, true
	}
	return nil, false
}

// forAccount maps the policy onto one account.
func (p *sudoPolicy) forAccount(name string, inGroup func(string) bool) AccountSudo {
	reasons := reasonSet{}
	out := AccountSudo{Grants: []Grant{}}
	if p.unresolved {
		reasons.add(reasonSudoPolicyUnresolved)
		out.Reasons = reasons.list()
		return out
	}
	reasons.merge(p.global)
	matchUser := func(us []sudoUser) (sudoUser, bool) {
		for _, u := range us {
			if (!u.group && u.name == name) || (u.group && inGroup(u.name)) {
				return u, true
			}
		}
		return sudoUser{}, false
	}
	for _, sr := range p.userReasons {
		if _, ok := matchUser(sr.users); ok {
			reasons.add(sr.reason)
		}
	}
	for _, rule := range p.rules {
		u, ok := matchUser(rule.users)
		if !ok {
			continue
		}
		if rule.unsupported {
			reasons.add(reasonSudoUnsupportedSyntax)
			continue
		}
		for _, hg := range rule.hosts {
			if hg.conditional {
				reasons.add(reasonSudoHostConditional)
			}
			if hg.overPaths {
				reasons.add(reasonLimitExceeded)
			}
			if !hg.applies {
				continue
			}
			for _, g := range hg.grants {
				gr := Grant{
					Source: rule.source, Via: u.via(), Runas: g.runas,
					Commands: "limited", CommandPaths: g.paths,
					ArgsRestricted: g.argsRestricted, NoPasswd: g.nopasswd,
				}
				if g.all {
					gr.Commands, gr.CommandPaths = "all", []string{}
				}
				out.Grants = append(out.Grants, gr)
			}
		}
	}
	out.Reasons = reasons.list()
	out.Complete = len(reasons) == 0
	return out
}
