package exposure

import (
	"bytes"
	"context"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// multiLineKeywords are printed by sshd -T once per entry.
var multiLineKeywords = map[string]bool{"allowusers": true, "denyusers": true, "allowgroups": true, "denygroups": true}

const (
	kwKeysCommand           = "authorizedkeyscommand"
	kwKeysCommandUser       = "authorizedkeyscommanduser"
	kwPrincipalsCommand     = "authorizedprincipalscommand"
	kwPrincipalsCommandUser = "authorizedprincipalscommanduser"
)

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
	for k := range sshdDefaults {
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
		if _, ok := sshdDefaults[kw]; !ok {
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
	seen              map[string]bool
	block             matchSettings
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
	unreportableMatch     bool
	globals               map[string]string
	derivationUnsupported bool
	providers             matchBlock // only the allowlisted path and user survive parsing
	blocks                []matchBlock
	files                 []inspectedFile
	reasons               reasonSet // file and parse reasons for the sshd category
	// readAll is set when every configuration file was read in full.
	readAll          bool
	configIncomplete bool
}

func (cfg sshdConfig) canDerive() bool {
	if !cfg.readAll || cfg.configIncomplete || cfg.derivationUnsupported || cfg.providers.parseErr {
		return false
	}
	for _, mb := range cfg.blocks {
		if mb.parseErr || mb.unsupported {
			return false
		}
	}
	return true
}

func (cfg sshdConfig) effective() map[string]*string {
	if !cfg.canDerive() {
		return nil
	}
	values := make(map[string]*string, len(sshdDefaults))
	for key, fallback := range sshdDefaults {
		v, ok := cfg.globals[key]
		if !ok {
			v = fallback
		}
		// sshd -T omits empty access lists; their wire value is null.
		if v == "" {
			values[key] = nil
		} else {
			values[key] = &v
		}
	}
	return values
}

// The report schema caps each setting at 4096 bytes. Config values are ASCII.
const maxConfigSettingBytes = 4096

func (cfg *sshdConfig) setGlobal(key string, args []string) {
	switch key {
	case kwKeysCommand, kwKeysCommandUser, kwPrincipalsCommand, kwPrincipalsCommandUser:
		cfg.providers.set(key, args)
		return
	}
	if _, ok := sshdDefaults[key]; !ok {
		return
	}
	previous, set := cfg.globals[key]
	if set && !multiLineKeywords[key] {
		return
	}
	v := configSetting(key, args)
	if set {
		if len(previous)+1+len(v) > maxConfigSettingBytes {
			cfg.derivationUnsupported = true
			return
		}
		v = previous + " " + v
	}
	cfg.globals[key] = v
}

func configSetting(key string, args []string) string {
	value := strings.Join(args, " ")
	switch key {
	case "allowusers", "denyusers", "allowgroups", "denygroups":
		return value
	case "authorizedkeysfile", "authorizedprincipalsfile", "revokedkeys", "trustedusercakeys":
		if strings.EqualFold(value, "none") {
			return "none"
		}
		return value
	}
	return normalizeValue(value)
}

func configValueSupported(key, value string, args []string) bool {
	if !validValue(value) || len(value) > maxConfigSettingBytes {
		return false
	}
	for _, arg := range args {
		if !validToken(arg) {
			return false
		}
	}
	switch key {
	case "pubkeyacceptedalgorithms", "casignaturealgorithms":
		// List modifiers and patterns require the installed binary's algorithm set.
		return len(args) == 1 && !strings.ContainsAny(value[:1], "+-^") && !strings.ContainsAny(value, "*?!") &&
			!slices.Contains(strings.Split(value, ","), "")
	case "authenticationmethods":
		if value == "any" {
			return true
		}
		for _, alternative := range args {
			for method := range strings.SplitSeq(alternative, ",") {
				name, device, qualified := strings.Cut(method, ":")
				if qualified && (name != "keyboard-interactive" || !validName(device)) {
					return false
				}
				switch name {
				case "publickey", "password", "keyboard-interactive", "hostbased", "gssapi-with-mic", "none":
				default:
					return false
				}
			}
		}
		return true
	case "allowusers", "denyusers", "allowgroups", "denygroups":
		return true
	case "authorizedkeysfile":
		for _, arg := range args {
			if strings.HasPrefix(arg, "~") {
				return false
			}
		}
		return true
	case "authorizedprincipalsfile", "trustedusercakeys", "revokedkeys":
		return len(args) == 1 && !strings.HasPrefix(value, "~")
	case "permitrootlogin":
		return value == "without-password" || value == "prohibit-password" || value == "forced-commands-only" || value == "yes" || value == "no"
	case "ignorerhosts":
		return value == "shosts-only" || value == "yes" || value == "no"
	default:
		return value == "yes" || value == "no"
	}
}

type inspectedFile struct {
	path  string
	mtime time.Time
}

const sshdConfigPath = "/etc/ssh/sshd_config"

// parseSSHDConfig reads global settings and Match blocks in Include order.
func parseSSHDConfig(src systemSource) sshdConfig {
	return parseSSHDConfigContext(context.Background(), src)
}

func parseSSHDConfigContext(ctx context.Context, src systemSource) sshdConfig {
	p := &sshdConfigParser{ctx: ctx, src: src, cfg: sshdConfig{providers: matchBlock{block: matchSettings{Sets: map[string]string{}}}, globals: map[string]string{}, reasons: reasonSet{}, readAll: true}, walker: includeWalker{src: src}}
	p.file(sshdConfigPath, 0, true)
	p.cfg.providers.finish()
	for i := range p.cfg.blocks {
		p.cfg.blocks[i].finish()
	}
	p.cfg.configIncomplete = p.cfg.configIncomplete || !p.cfg.readAll
	return p.cfg
}

type sshdConfigParser struct {
	ctx       context.Context
	exhausted bool
	src       systemSource
	cfg       sshdConfig
	walker    includeWalker
	current   *matchBlock
}

func (p *sshdConfigParser) fail(code string) {
	p.cfg.reasons.add(code)
	p.cfg.readAll = false
}

func (p *sshdConfigParser) active() bool {
	if p.ctx.Err() != nil {
		p.fail(reasonTimeout)
		return false
	}
	return !p.exhausted
}

func (p *sshdConfigParser) file(name string, depth int, required bool) {
	if !p.active() {
		return
	}
	if p.walker.files >= maxIncludeFiles {
		p.fail(reasonLimitExceeded)
		p.exhausted = true
		return
	}
	p.walker.file(name, depth, func(l loaded) {
		if l.status == statusAbsent && !required {
			// sshd skips an Include that matches nothing.
			return
		}
		if !l.usable() {
			if l.status == statusAbsent {
				p.fail(reasonFileUnreadable)
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
		forEachLine(l.data, func(line []byte, tooLong bool) bool {
			if !p.active() {
				return false
			}
			if tooLong {
				p.fail(reasonLimitExceeded)
				return true
			}
			line = bytes.TrimLeft(line, " \t")
			if len(line) == 0 || line[0] == '#' {
				return true
			}
			kw, args, ok := splitConfigLine(line)
			if !ok {
				p.fail(reasonParseError)
				return true
			}
			if !modeledSSHDDirective(kw, args) {
				p.cfg.derivationUnsupported = true
			}
			switch kw {
			case "challengeresponseauthentication", "dsaauthentication", "rsaauthentication", "skeyauthentication", "pubkeyacceptedkeytypes", "authorizedkeysfile2":
				p.cfg.derivationUnsupported = true
				// Keep existing Match settings for the wire even when the
				// global policy must come from an actual probe.
				switch kw {
				case "challengeresponseauthentication", "skeyauthentication":
					if p.current != nil {
						p.current.set("kbdinteractiveauthentication", args)
					}
				case "pubkeyacceptedkeytypes":
					if p.current != nil {
						p.current.set("pubkeyacceptedalgorithms", args)
					}
				}
				return true
			case "trustedusercakeys", "authorizedkeysfile", "revokedkeys":
				for _, arg := range args {
					if (len(args) != 1 || !strings.EqualFold(arg, "none")) && !validPath(arg) {
						p.cfg.derivationUnsupported = true
					}
				}
			case "allowusers", "denyusers", "allowgroups", "denygroups":
				// Some sshd versions retain an attached # as part of the
				// pattern. Never publish that text or guess a shorter pattern.
				for _, arg := range args {
					if strings.ContainsRune(arg, '#') {
						p.cfg.derivationUnsupported = true
						if p.current != nil {
							p.current.unsupported = true
							p.cfg.unreportableMatch = true
						}
						return true
					}
				}
				if p.current != nil {
					p.cfg.derivationUnsupported = true
				}
			}
			switch kw {
			case "include":
				if p.current != nil || depth != 0 {
					p.cfg.derivationUnsupported = true
				}
				if len(args) == 0 {
					p.fail(reasonParseError)
				}
				for _, a := range args {
					if !p.active() {
						return false
					}
					p.include(a, depth)
				}
			case "match":
				if len(p.cfg.blocks) >= maxMatchBlocks {
					p.cfg.reasons.add(reasonLimitExceeded)
					p.cfg.configIncomplete = true
					p.current = nil
					return true
				}
				p.cfg.blocks = append(p.cfg.blocks, newMatchBlock(args))
				p.current = &p.cfg.blocks[len(p.cfg.blocks)-1]
			default:
				if p.current != nil {
					p.current.set(kw, args)
				} else if !p.cfg.configIncomplete && !p.cfg.derivationUnsupported {
					p.cfg.setGlobal(kw, args)
				}
			}
			return true
		})
	}, p.fail)
}

func hasGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

func (p *sshdConfigParser) include(arg string, depth int) {
	if strings.HasPrefix(arg, "~") {
		p.fail(reasonParseError)
		return
	}
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
		p.includedFile(arg, depth+1, false)
		return
	}
	// POSIX character classes and collating elements have no path.Match equivalent.
	if strings.Contains(base, "[[:") || strings.Contains(base, "[[.") || strings.Contains(base, "[[=") {
		p.fail(reasonParseError)
		return
	}
	base = strings.ReplaceAll(base, "[!", "[^")
	if _, err := path.Match(base, ""); err != nil {
		p.fail(reasonParseError)
		return
	}
	if p.walker.files >= maxIncludeFiles {
		p.fail(reasonLimitExceeded)
		p.exhausted = true
		return
	}
	p.walker.files++ // A glob consumes a traversal slot even when it matches nothing.
	names, l := p.src.list(dir)
	p.cfg.reasons.merge(l.reasons)
	if len(l.reasons) > 0 {
		p.cfg.readAll = false
	}
	if l.status == statusAbsent {
		return
	}
	if l.status != statusRead {
		p.cfg.readAll = false
		return
	}
	var matched []string
	for _, n := range names {
		// OpenSSH globs match bytes, while path.Match consumes Unicode runes.
		if strings.ContainsFunc(n, func(r rune) bool { return r > 127 }) {
			p.cfg.derivationUnsupported = true
		}
		if ok, err := path.Match(base, n); err == nil && ok && (!strings.HasPrefix(n, ".") || strings.HasPrefix(base, ".")) {
			matched = append(matched, n)
		}
	}
	slices.Sort(matched)
	for _, n := range matched {
		p.includedFile(dir+"/"+n, depth+1, true)
	}
}

// includedFile restores the enclosing Match after each file, including each
// match of a glob. Save an index because appending can move the block slice.
func (p *sshdConfigParser) includedFile(name string, depth int, required bool) {
	saved := -1
	for i := range p.cfg.blocks {
		if p.current == &p.cfg.blocks[i] {
			saved = i
			break
		}
	}
	p.file(name, depth, required)
	p.current = nil
	if saved >= 0 {
		p.current = &p.cfg.blocks[saved]
	}
}

// Derive only from directives whose syntax we recognize. The packaged configs
// also contain a few directives that contribute no authentication settings.
func modeledSSHDDirective(kw string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, arg := range args {
		if !validToken(arg) || strings.ContainsAny(arg, `\#"'`) {
			return false
		}
	}
	if _, tracked := sshdDefaults[kw]; tracked {
		return configValueSupported(kw, configSetting(kw, args), args)
	}
	switch kw {
	case "include", "match":
		return true
	case "acceptenv":
		for _, name := range args {
			if strings.ContainsRune(name, '=') {
				return false
			}
		}
		return true
	case kwKeysCommand, kwPrincipalsCommand:
		return validPath(args[0]) || len(args) == 1 && strings.EqualFold(args[0], "none")
	case kwKeysCommandUser, kwPrincipalsCommandUser:
		return len(args) == 1 && validName(args[0])
	case "x11forwarding", "printmotd":
		return len(args) == 1 && (strings.EqualFold(args[0], "yes") || strings.EqualFold(args[0], "no"))
	case "subsystem":
		return len(args) == 2 && args[0] == "sftp" && (validPath(args[1]) || args[1] == "internal-sftp")
	}
	return false
}

// splitConfigLine splits "Keyword[=| ]args" with sshd's quoting rules.
func splitConfigLine(line []byte) (string, []string, bool) {
	s := strings.Trim(string(line), " \t")
	end := strings.IndexAny(s, " \t=")
	if end < 0 {
		end = len(s)
	}
	kw := s[:end]
	for i := range len(kw) {
		if !isAlnum(kw[i]) {
			// Leave the spelling unmodeled without discounting a successful -T.
			kw = ""
			break
		}
	}
	kw = strings.ToLower(kw)
	rest := strings.TrimLeft(s[end:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	args, ok := splitArgs(rest)
	return kw, args, ok
}

func splitArgs(s string) ([]string, bool) {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i == len(s) || s[i] == '#' {
			break
		}
		var word strings.Builder
		var quote byte
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) && (strings.ContainsRune(`"'\`, rune(s[i+1])) || quote == 0 && s[i+1] == ' ') {
				i++
				word.WriteByte(s[i])
			} else if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					word.WriteByte(c)
				}
			} else if c == '"' || c == '\'' {
				quote = c
			} else if c == ' ' || c == '\t' {
				break
			} else {
				word.WriteByte(c)
			}
			i++
		}
		if quote != 0 {
			return nil, false
		}
		out = append(out, word.String())
	}
	return out, true
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
	mb := matchBlock{block: matchSettings{Sets: map[string]string{}}}
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
	if len(c) > maxConfigSettingBytes {
		mb.parseErr = true
		return mb
	}
	mb.block.Criteria = &c
	return mb
}

func (mb *matchBlock) set(kw string, args []string) {
	if mb.seen == nil {
		mb.seen = map[string]bool{}
	}
	if mb.seen[kw] && !multiLineKeywords[kw] {
		return
	}
	mb.seen[kw] = true
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
	if _, ok := sshdDefaults[kw]; !ok {
		return
	}
	if !validValue(val) || len(val) > maxConfigSettingBytes {
		mb.parseErr = true
		return
	}
	val = configSetting(kw, args)
	if prev, ok := mb.block.Sets[kw]; ok && multiLineKeywords[kw] {
		val = prev + " " + val
		if len(val) > maxConfigSettingBytes {
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
