package exposure

import (
	"bytes"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// effectiveKeywords are the sshd -T keywords the report carries, exactly.
var effectiveKeywords = []string{
	"passwordauthentication", "kbdinteractiveauthentication", "usepam",
	"permitemptypasswords", "permitrootlogin", "pubkeyauthentication",
	"authenticationmethods", "pubkeyacceptedalgorithms", "casignaturealgorithms",
	"authorizedkeysfile", "authorizedprincipalsfile", "trustedusercakeys",
	"revokedkeys", "strictmodes", "gssapiauthentication", "kerberosauthentication",
	"kerberosorlocalpasswd", "hostbasedauthentication", "ignorerhosts",
	"ignoreuserknownhosts", "allowusers", "denyusers", "allowgroups", "denygroups",
}

// multiLineKeywords are printed by sshd -T once per entry.
var multiLineKeywords = map[string]bool{"allowusers": true, "denyusers": true, "allowgroups": true, "denygroups": true}

const (
	kwKeysCommand           = "authorizedkeyscommand"
	kwKeysCommandUser       = "authorizedkeyscommanduser"
	kwPrincipalsCommand     = "authorizedprincipalscommand"
	kwPrincipalsCommandUser = "authorizedprincipalscommanduser"
)

var effectiveSet = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range effectiveKeywords {
		m[k] = true
	}
	return m
}()

// providerCommand is an AuthorizedKeysCommand or AuthorizedPrincipalsCommand:
// the executable path only, never its arguments.
type providerCommand struct {
	path *string
	user *string
}

type sshdT struct {
	effective         map[string]*string
	keysCommand       *providerCommand
	principalsCommand *providerCommand
	parseErr          bool
}

// parseSSHDT reduces sshd -T output to the allowlisted keywords. Every other
// line is dropped unread; a value outside the grammar is null and counted.
func parseSSHDT(out []byte) sshdT {
	res := sshdT{effective: map[string]*string{}}
	for _, k := range effectiveKeywords {
		res.effective[k] = nil
	}
	internal := map[string]string{}
	forEachLine(out, func(line []byte, tooLong bool) bool {
		if tooLong {
			res.parseErr = true
			return true
		}
		kw, val, _ := strings.Cut(string(line), " ")
		kw = strings.ToLower(kw)
		val = strings.TrimSpace(val)
		switch kw {
		case kwKeysCommand, kwKeysCommandUser, kwPrincipalsCommand, kwPrincipalsCommandUser:
			internal[kw] = val
			return true
		}
		if !effectiveSet[kw] {
			return true
		}
		if !validValue(val) {
			res.parseErr = true
			res.effective[kw] = nil
			return true
		}
		val = normalizeValue(val)
		if multiLineKeywords[kw] && res.effective[kw] != nil {
			joined := *res.effective[kw] + " " + val
			if len(joined) > maxEffectiveValueLen {
				res.parseErr = true
				return true
			}
			val = joined
		}
		res.effective[kw] = &val
		return true
	})
	res.keysCommand = commandFrom(internal[kwKeysCommand], internal[kwKeysCommandUser])
	res.principalsCommand = commandFrom(internal[kwPrincipalsCommand], internal[kwPrincipalsCommandUser])
	return res
}

// normalizeValue lowercases a yes/no value as sshd -T prints it.
func normalizeValue(v string) string {
	switch l := strings.ToLower(v); l {
	case "yes", "no", "none", "any":
		return l
	}
	return v
}

func commandFrom(cmd, user string) *providerCommand {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || strings.EqualFold(cmd, "none") {
		return nil
	}
	pc := &providerCommand{}
	if fields := strings.Fields(cmd); len(fields) > 0 && validPath(fields[0]) {
		pc.path = &fields[0]
	}
	if user = strings.TrimSpace(user); validName(user) {
		pc.user = &user
	}
	return pc
}

// matchCriteria are the Match criteria the report re-emits, by lowercase
// name.
var matchCriteria = map[string]string{
	"user": "User", "group": "Group", "host": "Host", "localaddress": "LocalAddress",
	"localport": "LocalPort", "address": "Address", "rdomain": "RDomain",
}

type matchBlock struct {
	block             MatchBlock
	unsupported       bool
	parseErr          bool
	keysCommand       *providerCommand
	principalsCommand *providerCommand
	hasKeysCmd        bool
	hasPrincipalsCmd  bool
	keysCmdUser       string
	principalsCmdUser string
}

type sshdConfig struct {
	blocks  []matchBlock
	files   []inspectedFile
	reasons reasonSet // file and parse reasons for the sshd category
	// readAll is set when every configuration file was read in full.
	readAll bool
}

type inspectedFile struct {
	path  string
	mtime time.Time
}

const sshdConfigPath = "/etc/ssh/sshd_config"

// parseSSHDConfig reads sshd_config and its includes for Match blocks. Lines
// before the first Match are ignored: sshd -T already reports them.
func parseSSHDConfig(src systemSource) sshdConfig {
	p := &sshdConfigParser{src: src, cfg: sshdConfig{reasons: reasonSet{}, readAll: true}, onStack: map[string]bool{}}
	p.file(sshdConfigPath, 0)
	for i := range p.cfg.blocks {
		p.cfg.blocks[i].finish()
	}
	return p.cfg
}

type sshdConfigParser struct {
	src     systemSource
	cfg     sshdConfig
	onStack map[string]bool
	nfiles  int
	current *matchBlock
}

func (p *sshdConfigParser) fail(code string) {
	p.cfg.reasons.add(code)
	p.cfg.readAll = false
}

func (p *sshdConfigParser) file(name string, depth int) {
	if depth > maxIncludeDepth || p.nfiles >= maxIncludeFiles {
		p.fail(reasonLimitExceeded)
		return
	}
	if p.onStack[name] {
		p.fail(reasonParseError)
		return
	}
	p.nfiles++
	l := p.src.load(name)
	if l.status == statusAbsent && depth > 0 {
		// sshd skips an Include that matches nothing.
		return
	}
	if !l.usable() {
		if l.status == statusAbsent {
			p.cfg.files = append(p.cfg.files, inspectedFile{path: name})
			return
		}
		p.cfg.reasons.merge(l.reasons)
		if len(l.reasons) == 0 {
			p.cfg.reasons.add(reasonFileUnreadable)
		}
		p.cfg.readAll = false
		return
	}
	p.cfg.files = append(p.cfg.files, inspectedFile{path: name, mtime: l.mtime})
	p.onStack[name] = true
	defer delete(p.onStack, name)
	forEachLine(l.data, func(line []byte, tooLong bool) bool {
		if tooLong {
			p.fail(reasonLimitExceeded)
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		kw, args, ok := splitConfigLine(line)
		if !ok {
			p.fail(reasonParseError)
			return true
		}
		switch kw {
		case "include":
			saved := -1
			for i := range p.cfg.blocks {
				if p.current == &p.cfg.blocks[i] {
					saved = i
					break
				}
			}
			for _, a := range args {
				p.include(a, depth)
				if saved < 0 {
					p.current = nil
				} else {
					p.current = &p.cfg.blocks[saved]
				}
			}
		case "match":
			p.cfg.blocks = append(p.cfg.blocks, newMatchBlock(args))
			p.current = &p.cfg.blocks[len(p.cfg.blocks)-1]
		default:
			if p.current != nil {
				p.current.set(kw, args)
			}
		}
		return true
	})
}

func hasGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

func (p *sshdConfigParser) include(arg string, depth int) {
	if !strings.HasPrefix(arg, "/") {
		arg = "/etc/ssh/" + arg
	}
	dir, base := path.Split(arg)
	dir = strings.TrimSuffix(dir, "/")
	if hasGlob(dir) || !validPath(arg) {
		p.fail(reasonParseError)
		return
	}
	if !hasGlob(base) {
		p.file(arg, depth+1)
		return
	}
	names, l := p.src.list(dir)
	p.cfg.reasons.merge(l.reasons)
	if len(l.reasons) > 0 {
		p.cfg.readAll = false
	}
	if l.status == statusAbsent {
		return
	}
	if l.status != statusRead {
		p.cfg.reasons.merge(l.reasons)
		p.cfg.readAll = false
		return
	}
	var matched []string
	for _, n := range names {
		if ok, err := path.Match(base, n); err == nil && ok && !strings.HasPrefix(n, ".") {
			matched = append(matched, n)
		}
	}
	slices.Sort(matched)
	for _, n := range matched {
		p.file(dir+"/"+n, depth+1)
	}
}

// splitConfigLine splits "Keyword[=| ]args" with sshd's quoting rules.
func splitConfigLine(line []byte) (string, []string, bool) {
	s := strings.TrimSpace(string(line))
	end := strings.IndexAny(s, " \t=")
	if end < 0 {
		return strings.ToLower(s), nil, true
	}
	kw := strings.ToLower(s[:end])
	rest := strings.TrimLeft(s[end:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	args, ok := splitArgs(rest)
	return kw, args, ok
}

func splitArgs(s string) ([]string, bool) {
	var out []string
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return out, true
		}
		if s[0] == '"' {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				return nil, false
			}
			out = append(out, s[1:1+end])
			s = s[2+end:]
			continue
		}
		end := strings.IndexAny(s, " \t")
		if end < 0 {
			out = append(out, s)
			return out, true
		}
		out = append(out, s[:end])
		s = s[end:]
	}
}

func validCriterionValue(v string) bool {
	if v == "" || len(v) > 1024 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= ' ' || c > '~' || c == '"' || c == '\'' || c == '\\' || c == '`' {
			return false
		}
	}
	return true
}

func newMatchBlock(args []string) matchBlock {
	mb := matchBlock{block: MatchBlock{Sets: map[string]string{}}}
	var parts []string
	for i := 0; i < len(args); i++ {
		name, ok := matchCriteria[strings.ToLower(args[i])]
		if !ok {
			mb.unsupported = true
			return mb
		}
		if i+1 >= len(args) || !validCriterionValue(args[i+1]) {
			mb.parseErr = true
			return mb
		}
		parts = append(parts, name, args[i+1])
		i++
	}
	if len(parts) == 0 {
		mb.unsupported = true
		return mb
	}
	c := strings.Join(parts, " ")
	mb.block.Criteria = &c
	return mb
}

func (mb *matchBlock) set(kw string, args []string) {
	val := strings.Join(args, " ")
	switch kw {
	case kwKeysCommand, kwPrincipalsCommand:
		if len(args) == 0 {
			mb.parseErr = true
			return
		}
		if strings.EqualFold(args[0], "none") {
			return
		}
		pc := &providerCommand{}
		if validPath(args[0]) {
			pc.path = ptr(args[0])
		}
		if kw == kwKeysCommand {
			mb.keysCommand, mb.hasKeysCmd = pc, true
		} else {
			mb.principalsCommand, mb.hasPrincipalsCmd = pc, true
		}
		mb.block.Sets[kw] = "present"
		return
	case kwKeysCommandUser:
		mb.keysCmdUser = val
		return
	case kwPrincipalsCommandUser:
		mb.principalsCmdUser = val
		return
	}
	if !effectiveSet[kw] {
		return
	}
	if !validValue(val) {
		mb.parseErr = true
		return
	}
	val = normalizeValue(val)
	if prev, ok := mb.block.Sets[kw]; ok && multiLineKeywords[kw] {
		val = prev + " " + val
		if len(val) > maxEffectiveValueLen {
			mb.parseErr = true
			return
		}
	}
	mb.block.Sets[kw] = val
}

func (mb *matchBlock) finish() {
	if mb.keysCommand != nil && validName(mb.keysCmdUser) {
		mb.keysCommand.user = ptr(mb.keysCmdUser)
	}
	if mb.principalsCommand != nil && validName(mb.principalsCmdUser) {
		mb.principalsCommand.user = ptr(mb.principalsCmdUser)
	}
}

// sshdArgs is what a running sshd's command line says about its
// configuration. The arguments themselves are not kept.
type sshdArgs struct {
	configPath  string // "" for the default
	hasOverride bool   // -o, or an option this parser does not know
}

// sshd's getopt string: options followed by ':' take an argument.
const sshdOptString = "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV"

func parseSSHDArgs(argv []string) sshdArgs {
	var a sshdArgs
	takesArg := map[byte]bool{}
	known := map[byte]bool{}
	for i := 0; i < len(sshdOptString); i++ {
		known[sshdOptString[i]] = true
		if i+1 < len(sshdOptString) && sshdOptString[i+1] == ':' {
			takesArg[sshdOptString[i]] = true
			i++
		}
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			a.hasOverride = true
			continue
		}
		for j := 1; j < len(arg); j++ {
			c := arg[j]
			if !known[c] || c == ':' {
				a.hasOverride = true
				return a
			}
			if !takesArg[c] {
				continue
			}
			val := arg[j+1:]
			if val == "" {
				if i+1 >= len(argv) {
					a.hasOverride = true
					return a
				}
				i++
				val = argv[i]
			}
			switch c {
			case 'o':
				a.hasOverride = true
			case 'f':
				a.configPath = val
			}
			break
		}
	}
	return a
}

// procStat is the part of /proc/<pid>/stat correspondence needs.
type procStat struct {
	comm      string
	ppid      int
	startTick uint64
}

// parseProcStat parses /proc/<pid>/stat; comm is the text between the first
// '(' and the last ')'.
func parseProcStat(data []byte) (procStat, bool) {
	open := bytes.IndexByte(data, '(')
	closeIdx := bytes.LastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return procStat{}, false
	}
	fields := strings.Fields(string(data[closeIdx+1:]))
	// fields[0] is state (field 3); ppid is field 4, starttime field 22.
	if len(fields) < 20 {
		return procStat{}, false
	}
	ppid, err1 := strconv.Atoi(fields[1])
	start, err2 := strconv.ParseUint(fields[19], 10, 64)
	if err1 != nil || err2 != nil {
		return procStat{}, false
	}
	return procStat{comm: string(data[open+1 : closeIdx]), ppid: ppid, startTick: start}, true
}

// parseBootTime returns btime from /proc/stat.
func parseBootTime(data []byte) (int64, bool) {
	var bt int64
	ok := false
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if v, found := bytes.CutPrefix(line, []byte("btime ")); found {
			n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
			bt, ok = n, err == nil
			return false
		}
		return true
	})
	return bt, ok
}
