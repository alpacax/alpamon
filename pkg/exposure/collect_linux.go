//go:build linux

package exposure

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// collectorOptions are the collector's inputs. Production uses
// defaultOptions; tests point root and procRoot at a fixture tree, replace
// the sshd runner, and map their own uid onto the owners a host would have.
type collectorOptions struct {
	root     string
	procRoot string
	hostname func() string
	runSSHD  func(ctx context.Context) sshdRun
	mapOwner func(path string, uid uint32) uint32
	budget   time.Duration
}

func defaultOptions() collectorOptions {
	identity := func(_ string, uid uint32) uint32 { return uid }
	return collectorOptions{
		root:     "/",
		procRoot: "/proc",
		hostname: func() string { h, _ := os.Hostname(); return h },
		runSSHD: func(ctx context.Context) sshdRun {
			return runSSHDT(ctx, "/", identity)
		},
		mapOwner: identity,
		budget:   categoryBudget,
	}
}

// collector reads the report. It is long-lived so that a worker abandoned
// on a hung mount is remembered across reads: while one is outstanding for a
// category, the next read records that category as a timeout instead of
// starting a second worker behind it.
type collector struct {
	opts  collectorOptions
	busy  map[string]*atomic.Bool
	reads atomic.Int64
}

func newCollector(opts collectorOptions) *collector {
	c := &collector{opts: opts, busy: map[string]*atomic.Bool{}}
	for _, n := range categoryNames {
		c.busy[n] = &atomic.Bool{}
	}
	return c
}

// runBudget runs fn as the category's worker with the category budget. ok is
// false on a timeout, including when an earlier worker is still outstanding.
func runBudget[T any](ctx context.Context, c *collector, cat string, fn func(context.Context) T) (T, bool) {
	var zero T
	slot := c.busy[cat]
	if !slot.CompareAndSwap(false, true) {
		return zero, false
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.budget)
	done := make(chan T, 1)
	go func() {
		defer cancel()
		v := fn(ctx)
		slot.Store(false)
		done <- v
	}()
	select {
	case v := <-done:
		return v, true
	case <-ctx.Done():
		log.Debug().Str("category", cat).Msg("Exposure category read timed out.")
		return zero, false
	}
}

// accountsData is what the accounts category read.
type accountsData struct {
	entries         []passwdEntry
	groups          []groupEntry
	shells          map[string]bool
	nss             map[string][]string
	systemdAccounts bool
	systemdGroups   bool
	reasons         reasonSet
	usable          bool
	pwInPassw       bool
}

type shadowData struct {
	usable  bool
	infos   map[string]shadowInfo
	reasons reasonSet
}

type sshdData struct {
	installed  bool
	t          *sshdT // nil when sshd -T was not usable
	cfg        sshdConfig
	daemon     Daemon
	reasons    reasonSet
	usable     bool
	configRead bool
}

// collect reads the host once. Every category worker opens its own root
// descriptor and closes it when it ends, so a worker abandoned on a hung
// mount never walks from a descriptor the next read has closed or reused.
func (c *collector) collect(ctx context.Context) *Report {
	c.reads.Add(1)
	host := c.opts.hostname()
	var b assembly
	var wg sync.WaitGroup
	start := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}
	start(func() {
		b.acc, b.accOK = runBudget(ctx, c, catAccounts, func(context.Context) accountsData {
			return withFS(c, accountsData{reasons: unreadable()}, func(_ *fsReader, sys systemFiles) accountsData { return readAccounts(sys) })
		})
	})
	start(func() {
		b.sh, b.shOK = runBudget(ctx, c, catPasswords, func(context.Context) shadowData {
			return withFS(c, shadowData{reasons: unreadable()}, func(_ *fsReader, sys systemFiles) shadowData { return readShadow(sys) })
		})
	})
	start(func() {
		b.sshd, b.sshdOK = runBudget(ctx, c, catSSHD, func(ctx context.Context) sshdData {
			return withFS(c, sshdData{reasons: unreadable(), daemon: Daemon{Correspondence: "unresolved"}}, func(fs *fsReader, sys systemFiles) sshdData { return c.readSSHD(ctx, fs, sys) })
		})
	})
	start(func() {
		b.sudo, b.sudoOK = runBudget(ctx, c, catSudo, func(context.Context) sudoPolicy {
			return withFS(c, sudoPolicy{global: unreadable()}, func(_ *fsReader, sys systemFiles) sudoPolicy { return readSudoPolicy(sys, host) })
		})
	})
	wg.Wait()

	if b.accOK && b.acc.usable {
		accounts := b.acc.entries
		var t *sshdT
		var cfg sshdConfig
		if b.sshdOK {
			t, cfg = b.sshd.t, b.sshd.cfg
		}
		start(func() {
			b.keys, b.keysOK = runBudget(ctx, c, catKeys, func(context.Context) keysData {
				return withFS(c, keysData{reasons: unreadable()}, func(fs *fsReader, _ systemFiles) keysData { return readKeys(fs, accounts, t, cfg) })
			})
		})
		start(func() {
			b.certs, b.certsOK = runBudget(ctx, c, catCertificates, func(context.Context) certsData {
				return withFS(c, certsData{reasons: unreadable()}, func(fs *fsReader, sys systemFiles) certsData { return readCerts(fs, sys, accounts, t, cfg) })
			})
		})
		start(func() {
			b.trust, b.trustOK = runBudget(ctx, c, catTrust, func(context.Context) trustData {
				return withFS(c, trustData{reasons: unreadable()}, func(fs *fsReader, sys systemFiles) trustData { return readTrust(fs, sys, accounts, t, cfg) })
			})
		})
		start(func() {
			b.pty, b.ptyOK = runBudget(ctx, c, catPTY, func(context.Context) ptyData {
				return withFS(c, ptyData{reasons: unreadable()}, func(fs *fsReader, _ systemFiles) ptyData { return readPTY(fs, accounts) })
			})
		})
		wg.Wait()
	}
	return b.report()
}

func unreadable() reasonSet { return reasonSet{reasonFileUnreadable: {}} }

// withFS runs fn with a reader of its own over the collector's root.
func withFS[T any](c *collector, fail T, fn func(*fsReader, systemFiles) T) T {
	fs, err := newFSReader(c.opts.root, c.opts.mapOwner)
	if err != nil {
		return fail
	}
	defer fs.close()
	return fn(fs, systemFiles{f: fs})
}

func readAccounts(sys systemFiles) accountsData {
	d := accountsData{reasons: reasonSet{}}
	pw := sys.load("/etc/passwd")
	if !pw.usable() {
		d.reasons.merge(pw.reasons)
		if pw.status == statusAbsent {
			d.reasons.add(reasonFileUnreadable)
		}
		return d
	}
	d.usable = true
	res := parsePasswd(pw.data)
	// A password field other than "x" holds a hash; drop the bytes.
	clear(pw.data)
	d.entries = res.entries
	if res.unparsed > 0 {
		d.reasons.add(reasonParseError)
	}
	if res.overLimit {
		d.reasons.add(reasonLimitExceeded)
	}
	for _, e := range res.entries {
		d.pwInPassw = d.pwInPassw || e.passwordInPasswd
	}
	if gr := sys.load("/etc/group"); gr.usable() {
		g := parseGroup(gr.data)
		d.groups = g.groups
		if g.unparsed > 0 {
			d.reasons.add(reasonParseError)
		}
	} else if gr.status != statusAbsent {
		d.reasons.merge(gr.reasons)
	}
	if sh := sys.load("/etc/shells"); sh.usable() {
		d.shells = parseShells(sh.data)
	} else {
		d.shells = map[string]bool{}
		if sh.status != statusAbsent {
			d.reasons.merge(sh.reasons)
		}
	}
	if ns := sys.load("/etc/nsswitch.conf"); ns.usable() {
		var unparsed int
		d.nss, unparsed = parseNSSwitch(ns.data)
		if unparsed > 0 {
			d.reasons.add(reasonParseError)
		}
	} else if ns.status != statusAbsent {
		d.reasons.merge(ns.reasons)
	}
	if slices.Contains(d.nss["passwd"], "systemd") || slices.Contains(d.nss["group"], "systemd") {
		for _, path := range []string{"/var/lib/systemd/home", "/etc/userdb"} {
			names, l := sys.list(path)
			if l.status == statusAbsent {
				continue
			}
			if !l.complete() {
				d.reasons.merge(l.reasons)
				d.reasons.add(reasonFileUnreadable)
				d.systemdAccounts, d.systemdGroups = true, true
				continue
			}
			for _, name := range names {
				if path == "/var/lib/systemd/home" {
					if strings.HasSuffix(name, ".home") {
						d.systemdAccounts, d.systemdGroups = true, true
					}
				} else {
					d.systemdAccounts = d.systemdAccounts || strings.HasSuffix(name, ".user")
					d.systemdGroups = d.systemdGroups || strings.HasSuffix(name, ".group")
				}
			}
		}
	}
	return d
}

func readShadow(sys systemFiles) shadowData {
	d := shadowData{reasons: reasonSet{}}
	l := sys.load("/etc/shadow")
	if !l.usable() {
		d.reasons.merge(l.reasons)
		if l.status == statusAbsent {
			d.reasons.add(reasonFileUnreadable)
		}
		return d
	}
	d.usable = true
	var unparsed int
	d.infos, unparsed = parseShadow(l.data)
	clear(l.data)
	if unparsed > 0 {
		d.reasons.add(reasonParseError)
	}
	return d
}

func (c *collector) readSSHD(ctx context.Context, fs *fsReader, sys systemFiles) sshdData {
	d := sshdData{reasons: reasonSet{}, daemon: Daemon{Correspondence: "unresolved"}}
	run := c.opts.runSSHD(ctx)
	d.installed = !run.notInstalled
	switch {
	case run.notInstalled:
		d.reasons.add(reasonSSHDNotInstalled)
	case !run.ok:
		d.reasons.add(reasonSSHDUnavailable)
	default:
		t := parseSSHDT(run.out)
		clear(run.out)
		d.t = &t
		d.usable = true
		if t.parseErr {
			d.reasons.add(reasonParseError)
		}
	}
	if run.notInstalled {
		return d
	}
	d.cfg = parseSSHDConfig(sys)
	d.reasons.merge(d.cfg.reasons)
	d.configRead = d.cfg.readAll
	if d.cfg.readAll {
		d.usable = true
	}
	for _, mb := range d.cfg.blocks {
		if mb.unsupported {
			d.reasons.add(reasonSSHDMatchUnsupported)
		}
		if mb.parseErr {
			d.reasons.add(reasonParseError)
		}
		if len(mb.block.Sets) > 0 {
			d.reasons.add(reasonSSHDMatchConditional)
		}
	}
	d.daemon = c.correspondence(fs, d.cfg)
	if d.daemon.Correspondence != "established" {
		d.reasons.add(reasonSSHDConfigUnresolved)
	}
	return d
}

var socketUnits = []string{
	"/etc/systemd/system/sockets.target.wants/ssh.socket",
	"/etc/systemd/system/sockets.target.wants/sshd.socket",
}

func (c *collector) correspondence(fs *fsReader, cfg sshdConfig) Daemon {
	d := Daemon{Correspondence: "unresolved"}
	masters, ok := findSSHDMasters(c.opts.procRoot)
	if !ok {
		return d
	}
	switch len(masters) {
	case 0:
		socket := false
		for _, u := range socketUnits {
			if present, _ := fs.exists(u); present {
				socket = true
			}
		}
		if socket && cfg.readAll {
			// Socket activation reads the configuration per connection.
			d.Correspondence = "established"
		}
	case 1:
		m := masters[0]
		matches := m.args.configPath == "" || m.args.configPath == sshdConfigPath
		d.ConfigPathMatches = &matches
		if !matches || m.args.hasOverride || !cfg.readAll {
			return d
		}
		for _, f := range cfg.files {
			if !f.mtime.IsZero() && !f.mtime.Before(m.start) {
				return d
			}
		}
		d.Correspondence = "established"
	}
	return d
}

// sshdValue returns an effective value, or "" when sshd -T was not usable or
// did not print it.
func sshdValue(t *sshdT, kw string) string {
	if t == nil || t.effective[kw] == nil {
		return ""
	}
	return *t.effective[kw]
}

// enabledAnywhere reports whether kw is set to want in effective or in any
// Match block.
func enabledAnywhere(t *sshdT, cfg sshdConfig, kw, want string) bool {
	if sshdValue(t, kw) == want {
		return true
	}
	for _, mb := range cfg.blocks {
		if mb.block.Sets[kw] == want {
			return true
		}
	}
	return false
}

func setInAnyBlock(cfg sshdConfig, kw string) bool {
	for _, mb := range cfg.blocks {
		if _, ok := mb.block.Sets[kw]; ok {
			return true
		}
	}
	return false
}

// expandPath expands %h, %u and %% in an sshd file setting for one account.
// A relative result is taken from the home directory. ok is false for any
// other token or a result outside the path grammar.
func expandPath(tmpl, home, user string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] != '%' {
			b.WriteByte(tmpl[i])
			continue
		}
		if i+1 >= len(tmpl) {
			return "", false
		}
		i++
		switch tmpl[i] {
		case 'h':
			b.WriteString(home)
		case 'u':
			b.WriteString(user)
		case '%':
			b.WriteByte('%')
		default:
			return "", false
		}
	}
	p := b.String()
	if !strings.HasPrefix(p, "/") {
		if home == "/" {
			p = "/" + p
		} else {
			p = home + "/" + p
		}
	}
	return p, validPath(p)
}

func underHome(p, home string) bool {
	return home != "" && (home == "/" || strings.HasPrefix(p, home+"/"))
}

type accountKeys struct {
	home  Home
	files []KeyFile
}

type keysData struct {
	byUser  map[string]accountKeys
	reasons reasonSet
	usable  bool
}

func strictOK(ps pathStat, uid uint32) bool {
	return (ps.uid == 0 || ps.uid == uid) && ps.mode&0o022 == 0
}

// strictChain applies sshd's StrictModes rule to a file and its parent
// directories, up to the home directory or to "/" when the file is outside
// it.
func strictChain(file pathStat, dirs []pathStat, home string, uid uint32) bool {
	if !strictOK(file, uid) {
		return false
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if !strictOK(dirs[i], uid) {
			return false
		}
		if dirs[i].path == home {
			break
		}
	}
	return true
}

func readKeys(fs *fsReader, accounts []passwdEntry, t *sshdT, cfg sshdConfig) keysData {
	d := keysData{byUser: map[string]accountKeys{}, reasons: reasonSet{}}
	if t == nil {
		d.reasons.add(reasonFileUnreadable)
		return d
	}
	d.usable = true
	if v := sshdValue(t, "revokedkeys"); (v != "" && v != "none") || setInAnyBlock(cfg, "revokedkeys") {
		d.reasons.add(reasonRevocationUnresolved)
	}
	if setInAnyBlock(cfg, "authorizedkeysfile") {
		d.reasons.add(reasonPathTokenUnresolved)
	}
	tmpls := strings.Fields(sshdValue(t, "authorizedkeysfile"))
	if len(tmpls) == 1 && tmpls[0] == "none" {
		tmpls = nil
	}
	if sshdValue(t, "authorizedkeysfile") == "" {
		d.reasons.add(reasonFileUnreadable)
	}
	for _, acct := range accounts {
		ak := accountKeys{home: Home{Status: statusUnresolved}, files: []KeyFile{}}
		rule := ownerRule{uid: acct.uid}
		strict, strictKnown, noHome, anyRead := true, true, false, false
		if acct.home == "" {
			d.reasons.add(reasonHomeUnreadable, reasonStrictModesUnresolved)
			d.byUser[acct.name] = ak
			continue
		}
		dirs, hl := fs.statDir(acct.home, rule)
		ak.home.Status = hl.status
		switch hl.status {
		case statusRead:
			strict = strict && strictOK(dirs[len(dirs)-1], acct.uid)
			sshDirs, sl := fs.statDir(strings.TrimSuffix(acct.home, "/")+"/.ssh", rule)
			switch sl.status {
			case statusRead:
				strict = strict && strictOK(sshDirs[len(sshDirs)-1], acct.uid)
			case statusAbsent:
			default:
				strictKnown = false
			}
		case statusAbsent:
			// No home: nothing under it can be read, and every key file in
			// it is verified absent. There is no component to judge.
			noHome = true
		default:
			d.reasons.add(reasonHomeUnreadable)
			strictKnown = false
		}
		budget := maxKeysPerAccount
		seen := map[string]bool{}
		for _, tmpl := range tmpls {
			p, ok := expandPath(tmpl, acct.home, acct.name)
			if !ok {
				if !validValue(tmpl) || seen[tmpl] {
					continue
				}
				seen[tmpl] = true
				ak.files = append(ak.files, KeyFile{Envelope: Envelope{Path: tmpl, Status: statusUnresolved, Reasons: []string{reasonPathTokenUnresolved}}})
				d.reasons.add(reasonPathTokenUnresolved)
				strictKnown = false
				continue
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			kf, file, fdirs := readKeyFile(fs, p, rule, &budget)
			if underHome(p, acct.home) && hl.status != statusRead && hl.status != statusAbsent {
				kf.Reasons = appendReason(kf.Reasons, reasonHomeUnreadable)
			}
			d.reasons.add(kf.Reasons...)
			switch {
			case kf.Status == statusAbsent:
			case file != nil:
				home := ""
				if underHome(p, acct.home) {
					home = acct.home
				}
				strict = strict && strictChain(*file, fdirs, home, acct.uid)
				anyRead = true
			default:
				strictKnown = false
			}
			ak.files = append(ak.files, kf)
		}
		slices.SortFunc(ak.files, func(a, b KeyFile) int { return strings.Compare(a.Path, b.Path) })
		switch {
		case noHome && strictKnown && !anyRead:
		case strictKnown:
			ak.home.StrictModesOK = ptr(strict)
		default:
			d.reasons.add(reasonStrictModesUnresolved)
		}
		d.byUser[acct.name] = ak
	}
	return d
}

func appendReason(rs []string, r string) []string {
	if slices.Contains(rs, r) {
		return rs
	}
	rs = append(rs, r)
	slices.Sort(rs)
	return rs
}

// readKeyFile reads one authorized_keys source. The returned pathStat is
// the file's own, set when fstat succeeded.
func readKeyFile(fs *fsReader, p string, rule ownerRule, budget *int) (KeyFile, *pathStat, []pathStat) {
	l, dirs := fs.read(p, rule)
	kf := KeyFile{Envelope: l.envelope(p), Keys: []Key{}}
	if l.status != statusRead {
		return kf, nil, dirs
	}
	file := &pathStat{path: p, uid: l.uid, mode: l.mode}
	kf.OwnerUID = ptr(l.uid)
	kf.Mode = ptr(formatMode(l.mode))
	if l.data == nil {
		return kf, file, dirs
	}
	res := parseAuthorizedKeys(l.data, budget)
	clear(l.data)
	kf.Keys = res.keys
	kf.UnparsedLines = res.unparsed + res.tooLong
	rs := reasonSet{}
	if res.unparsed > 0 {
		rs.add(reasonParseError)
	}
	if res.tooLong > 0 || res.overLimit {
		rs.add(reasonLimitExceeded)
	}
	if len(rs) > 0 {
		kf.Complete = false
		for r := range rs {
			kf.Reasons = appendReason(kf.Reasons, r)
		}
	}
	if kf.Keys == nil {
		kf.Keys = []Key{}
	}
	return kf, file, dirs
}

func formatMode(mode uint32) string {
	const digits = "01234567"
	m := mode & 0o7777
	return string([]byte{digits[m>>9&7], digits[m>>6&7], digits[m>>3&7], digits[m&7]})
}

type certsData struct {
	userCA     *UserCA
	principals map[string][]PrincipalsFile
	reasons    reasonSet
	usable     bool
}

func readCerts(fs *fsReader, sys systemFiles, accounts []passwdEntry, t *sshdT, cfg sshdConfig) certsData {
	d := certsData{principals: map[string][]PrincipalsFile{}, reasons: reasonSet{}}
	if t == nil {
		d.reasons.add(reasonFileUnreadable)
		return d
	}
	d.usable = true
	if v := sshdValue(t, "revokedkeys"); (v != "" && v != "none") || setInAnyBlock(cfg, "revokedkeys") {
		d.reasons.add(reasonRevocationUnresolved)
	}
	if setInAnyBlock(cfg, "trustedusercakeys") || setInAnyBlock(cfg, "authorizedprincipalsfile") {
		d.reasons.add(reasonPathTokenUnresolved)
	}
	switch ca := sshdValue(t, "trustedusercakeys"); {
	case ca == "":
		d.reasons.add(reasonFileUnreadable)
	case ca == "none":
	case strings.Contains(ca, "%") || !validPath(ca):
		d.userCA = &UserCA{Envelope: Envelope{Path: ca, Status: statusUnresolved, Reasons: []string{reasonPathTokenUnresolved}}, CAs: []CA{}}
		d.reasons.add(reasonPathTokenUnresolved)
	default:
		l := sys.load(ca)
		u := &UserCA{Envelope: l.envelope(ca), CAs: []CA{}}
		if l.data != nil {
			cas, unparsed, tooLong := parseCAKeys(l.data)
			u.CAs = cas
			if unparsed > 0 {
				u.Complete = false
				u.Reasons = appendReason(u.Reasons, reasonParseError)
			}
			if tooLong {
				u.Complete = false
				u.Reasons = appendReason(u.Reasons, reasonLimitExceeded)
			}
		}
		d.reasons.add(u.Reasons...)
		d.userCA = u
	}
	tmpl := sshdValue(t, "authorizedprincipalsfile")
	if tmpl == "" {
		d.reasons.add(reasonFileUnreadable)
	}
	if tmpl == "" || tmpl == "none" {
		return d
	}
	for _, acct := range accounts {
		files := []PrincipalsFile{}
		p, ok := expandPath(tmpl, acct.home, acct.name)
		switch {
		case acct.home == "":
			d.reasons.add(reasonHomeUnreadable)
		case !ok:
			files = append(files, PrincipalsFile{Envelope: Envelope{Path: tmpl, Status: statusUnresolved, Reasons: []string{reasonPathTokenUnresolved}}, Entries: []PrincipalEntry{}})
			d.reasons.add(reasonPathTokenUnresolved)
		default:
			l, _ := fs.read(p, ownerRule{uid: acct.uid})
			pf := PrincipalsFile{Envelope: l.envelope(p), Entries: []PrincipalEntry{}}
			if l.data != nil {
				entries, unparsed, tooLong, over := parsePrincipalsFile(l.data)
				clear(l.data)
				pf.Entries = entries
				if unparsed > 0 {
					pf.Complete = false
					pf.Reasons = appendReason(pf.Reasons, reasonParseError)
				}
				if tooLong || over {
					pf.Complete = false
					pf.Reasons = appendReason(pf.Reasons, reasonLimitExceeded)
				}
			}
			if pf.Entries == nil {
				pf.Entries = []PrincipalEntry{}
			}
			d.reasons.add(pf.Reasons...)
			files = append(files, pf)
		}
		d.principals[acct.name] = files
	}
	return d
}

type trustData struct {
	files   map[string][]TrustFile
	system  []SystemTrustFile
	reasons reasonSet
	usable  bool
}

func readTrust(fs *fsReader, sys systemFiles, accounts []passwdEntry, t *sshdT, cfg sshdConfig) trustData {
	d := trustData{files: map[string][]TrustFile{}, system: []SystemTrustFile{}, reasons: reasonSet{}}
	if t == nil {
		d.reasons.add(reasonFileUnreadable)
		return d
	}
	d.usable = true
	kerberos := enabledAnywhere(t, cfg, "gssapiauthentication", "yes") || enabledAnywhere(t, cfg, "kerberosauthentication", "yes")
	hostbased := enabledAnywhere(t, cfg, "hostbasedauthentication", "yes")
	rhosts := hostbased || enabledAnywhere(t, cfg, "ignorerhosts", "no")
	if !kerberos && !rhosts {
		// With these authentications off the files are not access paths and
		// are not opened.
		return d
	}
	if kerberos {
		if l := sys.load("/etc/krb5.conf"); l.usable() {
			if krb5MappingUnresolved(l.data) {
				d.reasons.add(reasonKerberosMappingUnresolv)
			}
		} else if l.status != statusAbsent {
			d.reasons.add(reasonKerberosMappingUnresolv)
			d.reasons.merge(l.reasons)
		}
	}
	if hostbased {
		d.reasons.add(reasonHostbasedConditional, reasonHostbasedUnassessed)
	}
	if rhosts {
		for _, p := range []string{"/etc/hosts.equiv", "/etc/ssh/shosts.equiv"} {
			l := sys.load(p)
			st := SystemTrustFile{Envelope: l.envelope(p), Entries: []HostUser{}}
			if l.data != nil {
				entries, unparsed, tooLong := parseHostsEquiv(l.data)
				st.Entries = entries
				st.Complete, st.Reasons = markParse(st.Complete, st.Reasons, unparsed, tooLong)
			}
			if st.Entries == nil {
				st.Entries = []HostUser{}
			}
			d.reasons.add(st.Reasons...)
			d.system = append(d.system, st)
		}
	}
	for _, acct := range accounts {
		files := []TrustFile{}
		if acct.home == "" {
			d.reasons.add(reasonHomeUnreadable)
			d.files[acct.name] = files
			continue
		}
		var kinds []string
		if kerberos {
			kinds = append(kinds, "k5login")
		}
		if rhosts {
			kinds = append(kinds, "rhosts", "shosts")
		}
		for _, kind := range kinds {
			p, _ := expandPath("."+kind, acct.home, acct.name)
			l, _ := fs.read(p, ownerRule{uid: acct.uid})
			tf := TrustFile{Envelope: l.envelope(p), Kind: kind, Entries: []TrustEntry{}}
			if l.data != nil {
				var unparsed int
				var tooLong bool
				if kind == "k5login" {
					tf.Entries, unparsed, tooLong = parseK5Login(l.data)
				} else {
					var hu []HostUser
					hu, unparsed, tooLong = parseHostsEquiv(l.data)
					tf.Entries = hostUserEntries(hu)
				}
				clear(l.data)
				tf.Complete, tf.Reasons = markParse(tf.Complete, tf.Reasons, unparsed, tooLong)
			}
			if tf.Entries == nil {
				tf.Entries = []TrustEntry{}
			}
			if l.status == statusUnreadable || l.status == statusRejected {
				if _, hl := fs.statDir(acct.home, ownerRule{uid: acct.uid}); hl.status != statusRead {
					tf.Reasons = appendReason(tf.Reasons, reasonHomeUnreadable)
				}
			}
			d.reasons.add(tf.Reasons...)
			files = append(files, tf)
		}
		slices.SortFunc(files, func(a, b TrustFile) int { return strings.Compare(a.Path, b.Path) })
		d.files[acct.name] = files
	}
	return d
}

func markParse(complete bool, reasons []string, unparsed int, tooLong bool) (bool, []string) {
	if unparsed > 0 {
		complete = false
		reasons = appendReason(reasons, reasonParseError)
	}
	if tooLong {
		complete = false
		reasons = appendReason(reasons, reasonLimitExceeded)
	}
	return complete, reasons
}

type ptyData struct {
	byUser  map[string]*PTYLogin
	reasons reasonSet
	usable  bool
}

var (
	wtmpPaths   = []string{"/var/log/wtmp", "/var/log/wtmp.1"}
	lastlogPath = "/var/log/lastlog"
	// Newer accounting stores this read does not parse.
	wtmpdbPath   = "/var/lib/wtmpdb/wtmp.db"
	lastlog2Path = "/var/lib/lastlog/lastlog2.db"
)

func readPTY(fs *fsReader, accounts []passwdEntry) ptyData {
	d := ptyData{byUser: map[string]*PTYLogin{}, reasons: reasonSet{}}
	wtmp := map[string]ptyRecord{}
	wtmpFound := false
	for i, p := range wtmpPaths {
		l := fs.readTail(p, utmpSize)
		if l.status == statusAbsent {
			continue
		}
		if i == 0 {
			wtmpFound = true
		}
		d.reasons.merge(l.reasons)
		if l.data != nil {
			d.usable = true
			if parseWtmp(l.data, wtmp) > 0 {
				d.reasons.add(reasonParseError)
			}
		}
	}
	offsets := make([]int64, 0, len(accounts))
	for _, a := range accounts {
		offsets = append(offsets, int64(a.uid)*lastlogSize)
	}
	ll, recs := fs.readRecords(lastlogPath, lastlogSize, offsets)
	lastlogFound := ll.status != statusAbsent
	if lastlogFound {
		d.reasons.merge(ll.reasons)
		if ll.data != nil {
			d.usable = true
		}
	}
	wtmpdb, _ := fs.exists(wtmpdbPath)
	lastlog2, _ := fs.exists(lastlog2Path)
	switch {
	case !wtmpFound && !lastlogFound && (wtmpdb || lastlog2):
		d.reasons.add(reasonPTYSourceUnsupported)
	case !wtmpFound && !lastlogFound:
		d.reasons.add(reasonPTYSourceAbsent)
	case (!wtmpFound && wtmpdb) || (!lastlogFound && lastlog2):
		d.reasons.add(reasonPTYSourceUnsupported)
	}
	for _, a := range accounts {
		var best *PTYLogin
		var bestTime int64
		if rec, ok := wtmp[a.name]; ok {
			best, bestTime = rec.login("wtmp"), rec.time
		}
		if raw, ok := recs[int64(a.uid)*lastlogSize]; ok {
			if rec, ok := parseLastlog(raw); ok && rec.time > bestTime {
				best = rec.login("lastlog")
			}
			clear(raw)
		}
		d.byUser[a.name] = best
	}
	return d
}
