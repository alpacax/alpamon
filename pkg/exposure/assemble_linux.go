//go:build linux

package exposure

import (
	"slices"
	"strconv"
	"strings"
)

// assembly holds what each category worker returned; an ...OK of false
// means the worker timed out or was not started.
type assembly struct {
	acc     accountsData
	accOK   bool
	sh      shadowData
	shOK    bool
	sshd    sshdData
	sshdOK  bool
	sudo    sudoPolicy
	sudoOK  bool
	keys    keysData
	keysOK  bool
	certs   certsData
	certsOK bool
	trust   trustData
	trustOK bool
	pty     ptyData
	ptyOK   bool
}

type categoryState struct {
	reasons reasonSet
	usable  bool
}

func coverageOf(s categoryState) Coverage {
	if !s.usable && len(s.reasons) == 0 {
		s.reasons = reasonSet{reasonFileUnreadable: {}}
	}
	switch {
	case len(s.reasons) == 0:
		return Coverage{Status: coverageCovered, Reasons: []string{}}
	case s.usable:
		return Coverage{Status: coveragePartial, Reasons: s.reasons.list()}
	}
	return Coverage{Status: coverageUnknown, Reasons: s.reasons.list()}
}

func newReport() *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		Scope:         Scope{OS: "linux", Protocol: "ssh"},
		Categories:    map[string]Coverage{},
		External:      []External{},
		SSHD:          SSHD{MatchBlocks: []MatchBlock{}, Daemon: Daemon{Correspondence: "unresolved"}},
		SystemTrust:   []SystemTrustFile{},
		Accounts:      []Account{},
	}
}

func timedOut() categoryState { return categoryState{reasons: reasonSet{reasonTimeout: {}}} }

func (b *assembly) report() *Report {
	r := newReport()
	cats := map[string]categoryState{}
	for _, n := range categoryNames {
		cats[n] = categoryState{reasons: reasonSet{}}
	}
	set := func(n string, s categoryState) {
		if s.reasons == nil {
			s.reasons = reasonSet{}
		}
		cats[n] = s
	}

	// accounts
	accountsUsable := b.accOK && b.acc.usable
	if !b.accOK {
		set(catAccounts, timedOut())
	} else {
		set(catAccounts, categoryState{reasons: copySet(b.acc.reasons), usable: b.acc.usable})
	}
	// dependents carry the accounts failure when there is no account list
	depFail := func() categoryState {
		if !b.accOK {
			return timedOut()
		}
		return categoryState{reasons: reasonSet{reasonFileUnreadable: {}}}
	}

	// sshd
	var t *sshdT
	var cfg sshdConfig
	if !b.sshdOK {
		set(catSSHD, timedOut())
	} else {
		t, cfg = b.sshd.t, b.sshd.cfg
		set(catSSHD, categoryState{reasons: copySet(b.sshd.reasons), usable: b.sshd.usable})
		if t != nil {
			r.SSHD.Effective = t.effective
		}
		for _, mb := range cfg.blocks {
			r.SSHD.MatchBlocks = append(r.SSHD.MatchBlocks, mb.block)
		}
		r.SSHD.Daemon = b.sshd.daemon
	}

	// passwords
	switch {
	case !accountsUsable:
		set(catPasswords, depFail())
	case !b.shOK:
		set(catPasswords, timedOut())
	default:
		s := categoryState{reasons: copySet(b.sh.reasons), usable: b.sh.usable}
		if b.acc.pwInPassw {
			s.reasons.add(reasonParseError)
		}
		set(catPasswords, s)
	}
	if b.sshdOK && b.sshd.installed {
		pam := t == nil || (enabledAnywhere(t, cfg, "usepam", "yes") &&
			(enabledAnywhere(t, cfg, "passwordauthentication", "yes") || enabledAnywhere(t, cfg, "kbdinteractiveauthentication", "yes")))
		if pam {
			cats[catPasswords].reasons.add(reasonPAMBackendUnresolved)
		}
	}

	// keys, certificates, trust, pty: per-account sources
	sshdDep := func(name string, ok bool, s categoryState) {
		switch {
		case !accountsUsable:
			set(name, depFail())
		case !ok || !b.sshdOK:
			set(name, timedOut())
		default:
			set(name, s)
		}
	}
	sshdDep(catKeys, b.keysOK, categoryState{reasons: copySet(b.keys.reasons), usable: b.keys.usable})
	sshdDep(catCertificates, b.certsOK, categoryState{reasons: copySet(b.certs.reasons), usable: b.certs.usable})
	sshdDep(catTrust, b.trustOK, categoryState{reasons: copySet(b.trust.reasons), usable: b.trust.usable})
	switch {
	case !accountsUsable:
		set(catPTY, depFail())
	case !b.ptyOK:
		set(catPTY, timedOut())
	default:
		set(catPTY, categoryState{reasons: copySet(b.pty.reasons), usable: b.pty.usable})
	}
	if b.certsOK && b.sshdOK && accountsUsable {
		r.UserCA = b.certs.userCA
		if b.certs.failure != "" {
			if ca := sshdValue(t, "trustedusercakeys"); ca != "" && ca != "none" {
				r.UserCA = &UserCA{Envelope: failureEnvelope(ca, b.certs.failure), CAs: []CA{}}
			}
		}
	}
	if b.trustOK && b.sshdOK && accountsUsable {
		r.SystemTrust = b.trust.system
		if b.trust.failure != "" && (enabledAnywhere(t, cfg, "hostbasedauthentication", "yes") || enabledAnywhere(t, cfg, "ignorerhosts", "no")) {
			for _, p := range []string{"/etc/hosts.equiv", "/etc/ssh/shosts.equiv"} {
				r.SystemTrust = append(r.SystemTrust, SystemTrustFile{Envelope: failureEnvelope(p, b.trust.failure), Entries: []HostUser{}})
			}
		}
	}

	// sudo
	sudoState := categoryState{reasons: reasonSet{}}
	switch {
	case !accountsUsable:
		sudoState = depFail()
	case !b.sudoOK:
		sudoState = timedOut()
	default:
		sudoState.usable = !b.sudo.unresolved && (!b.sudo.global.has(reasonFileUnreadable) || len(b.sudo.rules) > 0)
	}

	// external sources
	ext := map[string]External{}
	addExt := func(e External, cats_ ...string) {
		ext[e.Kind+"\x00"+e.Scope] = e
		for _, c := range cats_ {
			if c == catSudo {
				sudoState.reasons.add(reasonExternalSource)
				continue
			}
			cats[c].reasons.add(reasonExternalSource)
		}
	}
	if b.accOK {
		if mods := nonFilesModules(b.acc.nss["passwd"], b.acc.systemdAccounts); len(mods) > 0 {
			addExt(External{Kind: externalNSSAccounts, Scope: "global", Sources: mods}, catAccounts)
		}
		if mods := nonFilesModules(b.acc.nss["group"], b.acc.systemdGroups); len(mods) > 0 {
			addExt(External{Kind: externalNSSGroups, Scope: "global", Sources: mods}, catAccounts, catSudo)
		}
		for _, m := range b.acc.nss["sudoers"] {
			if m == "sss" || m == "ldap" {
				addExt(External{Kind: externalLDAPSudo, Scope: "global"}, catSudo)
			}
		}
	}
	if t != nil {
		if pc := t.keysCommand; pc != nil {
			addExt(External{Kind: externalKeysCommand, Scope: "global", Path: pc.path, User: pc.user}, catKeys)
		}
		if pc := t.principalsCommand; pc != nil {
			addExt(External{Kind: externalPrincipalsComand, Scope: "global", Path: pc.path, User: pc.user}, catCertificates)
		}
		if sshdValue(t, "gssapiauthentication") == "yes" || sshdValue(t, "kerberosauthentication") == "yes" {
			addExt(External{Kind: externalKerberos, Scope: "global"}, catTrust, catPasswords)
		}
	}
	for i, mb := range cfg.blocks {
		scope := "match:" + strconv.Itoa(i)
		if mb.hasKeysCmd {
			addExt(External{Kind: externalKeysCommand, Scope: scope, Path: mb.keysCommand.path, User: mb.keysCommand.user}, catKeys)
		}
		if mb.hasPrincipalsCmd {
			addExt(External{Kind: externalPrincipalsComand, Scope: scope, Path: mb.principalsCommand.path, User: mb.principalsCommand.user}, catCertificates)
		}
		if mb.block.Sets["gssapiauthentication"] == "yes" || mb.block.Sets["kerberosauthentication"] == "yes" {
			addExt(External{Kind: externalKerberos, Scope: scope}, catTrust, catPasswords)
		}
	}
	for _, e := range ext {
		r.External = append(r.External, e)
	}
	slices.SortFunc(r.External, func(a, b External) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Scope, b.Scope)
	})

	// accounts
	if accountsUsable {
		groupsOf := membership(b.acc.entries, b.acc.groups)
		for _, e := range b.acc.entries {
			a := Account{Username: e.name, UID: e.uid, Groups: groupsOf[e.name]}
			if e.shell != "" {
				a.Shell = ptr(e.shell)
			}
			shell := e.shell
			if shell == "" {
				shell = "/bin/sh"
			}
			a.LoginShell = b.acc.shells[shell] && !isNoLoginShell(shell)
			a.Shadow = b.shadowFor(e.name)
			a.Home = Home{Status: statusTimeout}
			if b.keysOK && b.sshdOK {
				ak := b.keys.byUser[e.name]
				if b.keys.failure != "" {
					ak = failedAccountKeys(e, t, b.keys.failure)
				}
				a.Home, a.KeyFiles = ak.home, ak.files
				if a.Home.Status == "" {
					a.Home.Status = statusUnresolved
				}
			}
			if b.certsOK && b.sshdOK {
				a.PrincipalsFiles = b.certs.principals[e.name]
				if b.certs.failure != "" {
					a.PrincipalsFiles = failedAccountCerts(e, t, b.certs.failure)
				}
			}
			if b.trustOK && b.sshdOK {
				a.TrustFiles = b.trust.files[e.name]
				if b.trust.failure != "" {
					a.TrustFiles = failedAccountTrust(e, t, cfg, b.trust.failure)
				}
			}
			if b.ptyOK {
				a.LastPTYLogin = b.pty.byUser[e.name]
			}
			if b.sudoOK {
				member := map[string]bool{}
				for _, g := range a.Groups {
					member[g] = true
				}
				a.Sudo = b.sudo.forAccount(e.name, func(g string) bool { return member[g] })
			} else {
				a.Sudo = AccountSudo{Reasons: []string{reasonTimeout}, Grants: []Grant{}}
			}
			sudoState.reasons.add(a.Sudo.Reasons...)
			r.Accounts = append(r.Accounts, a)
		}
		slices.SortFunc(r.Accounts, func(x, y Account) int { return strings.Compare(x.Username, y.Username) })
	}
	set(catSudo, sudoState)

	for _, n := range categoryNames {
		r.Categories[n] = coverageOf(cats[n])
	}
	return r
}

func copySet(s reasonSet) reasonSet {
	out := reasonSet{}
	out.merge(s)
	return out
}

func nonFilesModules(mods []string, systemd bool) []string {
	var out []string
	for _, m := range mods {
		if m != "files" && (m != "systemd" || systemd) && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}

// membership returns each account's primary and supplementary group names,
// sorted.
func membership(entries []passwdEntry, groups []groupEntry) map[string][]string {
	byGID := map[uint32]string{}
	for _, g := range groups {
		if _, ok := byGID[g.gid]; !ok {
			byGID[g.gid] = g.name
		}
	}
	out := map[string][]string{}
	add := func(user, group string) {
		if len(out[user]) < maxGroupsPerAccount && !slices.Contains(out[user], group) {
			out[user] = append(out[user], group)
		}
	}
	known := map[string]bool{}
	for _, e := range entries {
		known[e.name] = true
		out[e.name] = []string{}
		if name, ok := byGID[e.gid]; ok {
			add(e.name, name)
		}
	}
	for _, g := range groups {
		for _, m := range g.members {
			if known[m] {
				add(m, g.name)
			}
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

func (b *assembly) shadowFor(name string) Shadow {
	s := Shadow{Status: shadowUnreadable, PasswordState: passwordUnknown}
	if !b.shOK || !b.sh.usable {
		return s
	}
	info, ok := b.sh.infos[name]
	if !ok {
		s.Status = shadowNoEntry
		return s
	}
	return Shadow{
		Status:         shadowRead,
		PasswordState:  info.state,
		LastChangeDays: info.lastChange,
		ExpireDays:     info.expire,
		InactiveDays:   info.inactive,
	}
}
