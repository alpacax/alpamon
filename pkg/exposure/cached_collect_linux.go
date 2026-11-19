//go:build linux

package exposure

import "strconv"

func readAccounts(sys systemFiles) accountsData {
	return cachedSource(sys.f, "accounts:/etc/passwd", nil, func(f *fsReader) accountsData {
		return readAccountsUncached(systemFiles{f: f})
	}, func(d accountsData) bool { return d.usable && len(d.reasons) == 0 }, immutable[accountsData])
}

func readShadow(sys systemFiles) shadowData {
	return cachedSource(sys.f, "shadow:/etc/shadow", nil, func(f *fsReader) shadowData {
		return readShadowUncached(systemFiles{f: f})
	}, func(d shadowData) bool { return d.usable && len(d.reasons) == 0 }, immutable[shadowData])
}

func readCachedSudo(sys systemFiles, host string) sudoPolicy {
	return cachedSource(sys.f, "sudo:/etc/sudoers", host, func(f *fsReader) sudoPolicy {
		return readSudoPolicy(systemFiles{f: f}, host)
	}, func(d sudoPolicy) bool {
		if d.failed || d.unresolved || len(d.global) != 0 || len(d.userReasons) != 0 {
			return false
		}
		for _, rule := range d.rules {
			if rule.unsupported {
				return false
			}
			for _, host := range rule.hosts {
				if host.conditional || host.overPaths {
					return false
				}
			}
		}
		return true
	}, immutable[sudoPolicy])
}

func readCachedSSHDConfig(sys systemFiles) sshdConfig {
	return cachedSource(sys.f, "sshd:"+sshdConfigPath, nil, func(f *fsReader) sshdConfig {
		return parseSSHDConfig(systemFiles{f: f})
	}, func(d sshdConfig) bool { return d.readAll && !d.configIncomplete && len(d.reasons) == 0 }, immutable[sshdConfig])
}

type cachedKeyFile struct {
	file      keyFile
	stat      *pathStat
	dirs      []pathStat
	remaining int
}

func cloneKeyFile(v cachedKeyFile) cachedKeyFile {
	v.file = cloneSourceFile(v.file)
	return v
}

func readKeyFile(fs *fsReader, p string, rule ownerRule, budget *int) (keyFile, *pathStat, []pathStat) {
	input := struct {
		Rule   ownerRule
		Budget int
	}{rule, *budget}
	v := cachedSource(fs, "keys:"+strconv.FormatUint(uint64(rule.uid), 10)+":"+p, input, func(f *fsReader) cachedKeyFile {
		remaining := *budget
		file, stat, dirs := readKeyFileUncached(f, p, rule, &remaining)
		return cachedKeyFile{file, stat, dirs, remaining}
	}, func(v cachedKeyFile) bool { return v.file.Status == statusRead && v.file.Complete }, cloneKeyFile)
	*budget = v.remaining
	return v.file, v.stat, v.dirs
}

func readParsedFile[T any](fs *fsReader, p string, rule ownerRule, kind string, parse func(loaded) T, complete func(T) bool) T {
	key := kind + ":" + p
	if !rule.system {
		key = kind + ":" + strconv.FormatUint(uint64(rule.uid), 10) + ":" + p
	}
	return cachedSource(fs, key, rule, func(f *fsReader) T {
		l, _ := f.read(p, rule)
		defer clear(l.data)
		return parse(l)
	}, complete, cloneSourceFile[T])
}

func readCAFile(fs *fsReader, p string) *userCA {
	return readParsedFile(fs, p, ownerRule{system: true}, "ca", func(l loaded) *userCA {
		u := &userCA{envelope: l.envelope(p), CAs: []caKey{}}
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
		return u
	}, func(v *userCA) bool { return v.Status == statusRead && v.Complete })
}

func readPrincipalsSource(fs *fsReader, p string, rule ownerRule) principalsFile {
	return readParsedFile(fs, p, rule, "principals", func(l loaded) principalsFile {
		pf := principalsFile{envelope: l.envelope(p), Entries: []principalEntry{}}
		if l.data != nil {
			entries, unparsed, tooLong, over := parsePrincipalsFile(l.data)
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
			pf.Entries = []principalEntry{}
		}
		return pf
	}, func(v principalsFile) bool { return v.Status == statusRead && v.Complete })
}

func readSystemTrustSource(fs *fsReader, p string) systemTrustFile {
	return readParsedFile(fs, p, ownerRule{system: true}, "system-trust", func(l loaded) systemTrustFile {
		st := systemTrustFile{envelope: l.envelope(p), Entries: []hostUser{}}
		if l.data != nil {
			entries, unparsed, tooLong := parseHostsEquiv(l.data)
			st.Entries = entries
			st.Complete, st.Reasons = markParse(st.Complete, st.Reasons, unparsed, tooLong)
		}
		if st.Entries == nil {
			st.Entries = []hostUser{}
		}
		return st
	}, func(v systemTrustFile) bool { return v.Status == statusRead && v.Complete })
}

func readTrustSource(fs *fsReader, p string, rule ownerRule, kind string) trustFile {
	return readParsedFile(fs, p, rule, "trust-"+kind, func(l loaded) trustFile {
		tf := trustFile{envelope: l.envelope(p), Kind: kind, Entries: []trustEntry{}}
		if l.data != nil {
			var unparsed int
			var tooLong bool
			if kind == "k5login" {
				tf.Entries, unparsed, tooLong = parseK5Login(l.data)
			} else {
				var hu []hostUser
				hu, unparsed, tooLong = parseHostsEquiv(l.data)
				tf.Entries = hostUserEntries(hu)
			}
			tf.Complete, tf.Reasons = markParse(tf.Complete, tf.Reasons, unparsed, tooLong)
		}
		if tf.Entries == nil {
			tf.Entries = []trustEntry{}
		}
		return tf
	}, func(v trustFile) bool { return v.Status == statusRead && v.Complete })
}

type kerberosSource struct {
	usable  bool
	status  string
	reasons reasonSet
	mapping bool
}

func readKerberosSource(fs *fsReader) kerberosSource {
	return cachedSource(fs, "kerberos:/etc/krb5.conf", nil, func(f *fsReader) kerberosSource {
		l, _ := f.read("/etc/krb5.conf", ownerRule{system: true})
		defer clear(l.data)
		return kerberosSource{l.usable(), l.status, l.reasons, l.usable() && krb5MappingUnresolved(l.data)}
	}, func(v kerberosSource) bool { return v.usable && len(v.reasons) == 0 && !v.mapping }, immutable[kerberosSource])
}

type wtmpSource struct {
	status  string
	reasons reasonSet
	usable  bool
	records map[string]ptyRecord
}

func readWtmpSource(fs *fsReader, p string) wtmpSource {
	return cachedSource(fs, "wtmp:"+p, nil, func(f *fsReader) wtmpSource {
		l := f.readTail(p, utmpSize)
		defer clear(l.data)
		v := wtmpSource{l.status, l.reasons, l.data != nil, map[string]ptyRecord{}}
		if l.data != nil && parseWtmp(l.data, v.records) > 0 {
			v.reasons.add(reasonParseError)
		}
		return v
	}, func(v wtmpSource) bool { return v.usable && len(v.reasons) == 0 }, immutable[wtmpSource])
}

type lastlogSource struct {
	status  string
	reasons reasonSet
	usable  bool
	records map[int64]ptyRecord
}

func readLastlogSource(fs *fsReader, offsets []int64) lastlogSource {
	return cachedSource(fs, "lastlog:"+lastlogPath, offsets, func(f *fsReader) lastlogSource {
		l, records := f.readRecords(lastlogPath, lastlogSize, offsets)
		v := lastlogSource{l.status, l.reasons, l.data != nil, map[int64]ptyRecord{}}
		for offset, raw := range records {
			if rec, ok := parseLastlog(raw); ok {
				v.records[offset] = rec
			}
			clear(raw)
		}
		return v
	}, func(v lastlogSource) bool { return v.usable && len(v.reasons) == 0 }, immutable[lastlogSource])
}
