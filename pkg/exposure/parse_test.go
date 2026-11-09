package exposure

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Public test keys; the fingerprints were checked with ssh-keygen -l.
const (
	testEd0 = "AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	testEd1 = "AAAAC3NzaC1lZDI1NTE5AAAAIK89ICZPnCbvCFtc5Tf0F9QkA3oJY6Y4b/bQUOW/dzcU"
	fpEd0   = "SHA256:lbmsoA0yIEcEiVDRnMWuzm+nV+3ZEEpVIURqFoeSspg"
)

func TestClassifyPassword(t *testing.T) {
	for field, want := range map[string]string{
		"":                        passwordEmpty,
		"*":                       passwordNone,
		"!":                       passwordNone,
		"!!":                      passwordNone,
		"!*":                      passwordNone,
		"!$6$salt$hash":           passwordLocked,
		"!!$6$salt$hash":          passwordLocked,
		"!abcdefghij.lm":          passwordLocked,
		"$6$salt$hashvalue/./":    passwordSet,
		"$y$j9T$salt$hash":        passwordSet,
		"$2b$10$abcdefghijklmnop": passwordSet,
		"abcdefghij.lm":           passwordSet,
		"_J9..rasmBYk8r9AiWNc":    passwordSet,
		"*LK*":                    passwordUnknown,
		"x":                       passwordUnknown,
		"!!!":                     passwordUnknown,
		"$":                       passwordUnknown,
		"$6":                      passwordUnknown,
		"!**":                     passwordUnknown,
	} {
		assert.Equal(t, want, classifyPassword([]byte(field)), "field %q", field)
	}
}

func TestParseShadowKeepsNoHashBytes(t *testing.T) {
	data := "alice:$6$LEAKCANARY$hash:20100:0:99999:7:30:20500:\n" +
		"bob::0::::::\n" +
		"bad line\n" +
		"carol:!:x::::::\n"
	infos, unparsed := parseShadow([]byte(data))
	assert.Equal(t, 1, unparsed)
	assert.Equal(t, shadowInfo{state: passwordSet, lastChange: ptr(int64(20100)), inactive: ptr(int64(30)), expire: ptr(int64(20500))}, infos["alice"])
	assert.Equal(t, shadowInfo{state: passwordEmpty, lastChange: ptr(int64(0))}, infos["bob"], "0 is a forced change")
	assert.True(t, infos["carol"].parseErr)
	assert.NotContains(t, fmt.Sprintf("%+v", infos), "LEAKCANARY")
}

func TestParsePasswd(t *testing.T) {
	res := parsePasswd([]byte("root:x:0:0:root:/root:/bin/bash\n+nis::::::\nroot:x:9:9::/:/bin/sh\nweird name:x:1:1::/:/bin/sh\nsvc:hash:5:5::/srv:\n"))
	require.Len(t, res.entries, 2)
	assert.Equal(t, 3, res.unparsed)
	assert.Equal(t, passwdEntry{name: "svc", uid: 5, gid: 5, home: "/srv", passwordInPasswd: true}, res.entries[1])
	assert.False(t, res.entries[0].passwordInPasswd)

	var b strings.Builder
	for i := range maxAccounts + 1 {
		fmt.Fprintf(&b, "u%d:x:%d:%d::/home/u:/bin/sh\n", i, i, i)
	}
	res = parsePasswd([]byte(b.String()))
	assert.Len(t, res.entries, maxAccounts)
	assert.True(t, res.overLimit)
}

func TestDuplicateAccountEntries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		passwd string
		group  string
		shadow string
	}{
		{
			name:   "different metadata",
			passwd: "deploy:x:1001:1001::/home/deploy:/bin/bash\ndeploy:hash:2002:2002::/home/dropped:/bin/sh\n",
			group:  "ops:x:1001:deploy\nops:x:2002:root\n",
			shadow: "deploy:!:20100:0:99999:7:30:20500:\ndeploy::1:0:99999:7:1:2:\n",
		},
		{
			name:   "repeated duplicates",
			passwd: "deploy:x:1001:1001::/home/deploy:/bin/bash\n" + strings.Repeat("deploy:x:2002:2002::/home/dropped:/bin/sh\n", 2),
			group:  "ops:x:1001:deploy\n" + strings.Repeat("ops:x:2002:root\n", 2),
			shadow: "deploy:!:20100:0:99999:7:30:20500:\n" + strings.Repeat("deploy::1:0:99999:7:1:2:\n", 2),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pw := parsePasswd([]byte(tc.passwd))
			assert.Equal(t, []passwdEntry{{name: "deploy", uid: 1001, gid: 1001, home: "/home/deploy", shell: "/bin/bash"}}, pw.entries)
			assert.Equal(t, strings.Count(tc.passwd, "\n")-1, pw.unparsed)
			assert.False(t, pw.overLimit)
			gr := parseGroup([]byte(tc.group))
			assert.Equal(t, []groupEntry{{name: "ops", gid: 1001, members: []string{"deploy"}}}, gr.groups)
			assert.Equal(t, strings.Count(tc.group, "\n")-1, gr.unparsed)
			sh, unparsed := parseShadow([]byte(tc.shadow))
			assert.Equal(t, map[string]shadowInfo{"deploy": {state: passwordNone, lastChange: ptr(int64(20100)), inactive: ptr(int64(30)), expire: ptr(int64(20500))}}, sh)
			assert.Equal(t, strings.Count(tc.shadow, "\n")-1, unparsed)
		})
	}
}

func TestPasswdDuplicatesDoNotCountTowardCap(t *testing.T) {
	for _, count := range []int{maxAccounts - 1, maxAccounts, maxAccounts + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var data strings.Builder
			for i := range count {
				fmt.Fprintf(&data, "u%d:x:%d:1001::/home/first:/bin/sh\n", i, i)
				fmt.Fprintf(&data, "u%d:x:%d:1001::/home/dropped:/bin/sh\n", i, i)
			}
			got := parsePasswd([]byte(data.String()))
			assert.Len(t, got.entries, min(count, maxAccounts))
			assert.Equal(t, min(count, maxAccounts), got.unparsed)
			assert.Equal(t, count > maxAccounts, got.overLimit)
		})
	}
}

func TestParseKeyOptions(t *testing.T) {
	for _, tc := range []struct {
		in    string
		ok    bool
		names []string
	}{
		{`no-pty,from="10.0.0.0/8,!10.0.0.5" `, true, []string{"from", "no-pty"}},
		{`command="echo \"hi\" LEAKCANARY",restrict `, true, []string{"command", "restrict"}},
		{`NO-PTY `, true, []string{"no-pty"}},
		{`environment="A=B",environment="C=D" `, true, []string{"environment"}},
		{`unknown-opt `, false, nil},
		{`no-pty="x" `, false, nil},
		{`command=x `, false, nil},
		{`command="unterminated `, false, nil},
		{`from="not a pattern" `, false, nil},
		{`from="` + strings.Repeat("a", maxFromBytes+1) + `" `, false, nil},
		{`principals="a,b c" `, false, nil},
		{`expiry-time="2027" `, false, nil},
		{`expiry-time="20271231Z" `, true, []string{"expiry-time"}},
		{`no-pty,,no-pty `, false, nil},
	} {
		opts, _, ok := parseKeyOptions([]byte(tc.in))
		assert.Equal(t, tc.ok, ok, tc.in)
		if ok {
			assert.Equal(t, tc.names, opts.names, tc.in)
			assert.NotContains(t, fmt.Sprintf("%+v", opts), "LEAKCANARY")
		}
	}
}

func TestParseKeyLine(t *testing.T) {
	kl, ok := parseKeyLine([]byte("ssh-ed25519 " + testEd0 + " alice@example.com"))
	require.True(t, ok)
	assert.Equal(t, fpEd0, kl.key.fingerprint)
	assert.Equal(t, 256, kl.key.bits)
	assert.Equal(t, "alice@example.com", *kl.comment)

	kl, ok = parseKeyLine([]byte("ssh-ed25519 " + testEd0 + " " + strings.Repeat("é", 130) + "\x1b[31m"))
	require.True(t, ok)
	assert.Equal(t, maxCommentRunes, len([]rune(*kl.comment)))
	assert.True(t, kl.truncated)

	kl, ok = parseKeyLine([]byte("ssh-ed25519 " + testEd0 + " a\x00b\x7fc\xffd"))
	require.True(t, ok)
	assert.Equal(t, "abcd", *kl.comment)

	for _, bad := range []string{
		"ssh-ed25519",
		"ssh-ed25519 !!!!",
		"ssh-rsa " + testEd0, // blob type differs from the line's
		"ssh-ed25519-cert-v01@openssh.com " + testEd0, // certificates are not keys
		"ssh-ed25519 " + testEd0[:len(testEd0)-4],
	} {
		_, ok := parseKeyLine([]byte(bad))
		assert.False(t, ok, bad)
	}
}

func TestParseAuthorizedKeysVariants(t *testing.T) {
	data := strings.Join([]string{
		"ssh-ed25519 " + testEd0 + " a",
		"ssh-ed25519 " + testEd0 + " a",
		`no-pty ssh-ed25519 ` + testEd0 + " a",
		`cert-authority,principals="ops" ssh-ed25519 ` + testEd0 + " a",
		`command="LEAKCANARY" ssh-ed25519 ` + testEd1,
		"garbage LEAKCANARY",
		strings.Repeat("x", maxLineBytes+1),
		"",
	}, "\n")
	budget := maxKeysPerAccount
	res := parseAuthorizedKeys([]byte(data), &budget)
	assert.Equal(t, 1, res.unparsed)
	assert.Equal(t, 1, res.tooLong)
	require.Len(t, res.keys, 2)
	var ed0 key
	for _, k := range res.keys {
		if k.Fingerprint == fpEd0 {
			ed0 = k
		}
	}
	require.Len(t, ed0.Authorizations, 3, "restrictions are never merged")
	counts := map[string]int{}
	for _, a := range ed0.Authorizations {
		counts[a.Role+fmt.Sprint(a.Options)] = a.Count
	}
	assert.Equal(t, map[string]int{"user_key[]": 2, "user_key[no-pty]": 1, "cert_authority[cert-authority principals]": 1}, counts)
	out, err := encodeValue(res.keys)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "LEAKCANARY")
	assert.NotContains(t, string(out), testEd0)
	assert.Equal(t, maxKeysPerAccount-5, budget)

	budget = 1
	res = parseAuthorizedKeys([]byte(data), &budget)
	assert.True(t, res.overLimit)
	assert.Len(t, res.keys, 1)
}

func TestParsePrincipalsFile(t *testing.T) {
	entries, unparsed, tooLong, over := parsePrincipalsFile([]byte(
		"deploy\nfrom=\"192.0.2.0/24\",command=\"LEAKCANARY\" backup\ntwo words\ncert-authority x\ndeploy\n"))
	assert.Equal(t, 2, unparsed)
	assert.False(t, tooLong)
	assert.False(t, over)
	require.Len(t, entries, 2)
	out, err := encodeValue(entries)
	require.NoError(t, err)
	assert.Equal(t, `[{"from":"192.0.2.0/24","options":["command","from"],"principals":["backup"]},{"from":null,"options":[],"principals":["deploy"]}]`, string(out))

	var b strings.Builder
	for i := range maxPrincipalEntries + 1 {
		fmt.Fprintf(&b, "p%d\n", i)
	}
	entries, _, _, over = parsePrincipalsFile([]byte(b.String()))
	assert.True(t, over)
	assert.Len(t, entries, maxPrincipalEntries)
}

func TestParseCAKeys(t *testing.T) {
	cas, unparsed, _ := parseCAKeys([]byte("ssh-ed25519 " + testEd0 + " ca\nssh-ed25519 " + testEd0 + " dup\ncert-authority ssh-ed25519 " + testEd1 + "\n"))
	assert.Equal(t, []caKey{{Fingerprint: fpEd0, Type: "ssh-ed25519", Bits: 256}}, cas)
	assert.Equal(t, 1, unparsed, "options are not allowed in a user-CA file")
}

func TestParseTrust(t *testing.T) {
	k5, unparsed, _ := parseK5Login([]byte("alice@EXAMPLE.COM\nbob\nbad principal\na@b@c\n"))
	assert.Equal(t, 2, unparsed)
	assert.Len(t, k5, 2)
	hu, unparsed, _ := parseHostsEquiv([]byte("host.example.com\nhost2 root\n+\n-host\n@netgroup\nh u extra\n"))
	assert.Equal(t, 4, unparsed)
	assert.Equal(t, []hostUser{{Host: "host.example.com"}, {Host: "host2", User: ptr("root")}}, hu)
	assert.True(t, krb5MappingUnresolved([]byte("[libdefaults]\n k5login_directory = /etc/k5\n")))
	assert.True(t, krb5MappingUnresolved([]byte("includedir /etc/krb5.conf.d/\n")))
	assert.False(t, krb5MappingUnresolved([]byte("[libdefaults]\n default_realm = EXAMPLE.COM\n=\n")))
}

func TestParseSSHDT(t *testing.T) {
	out := strings.Join([]string{
		"passwordauthentication YES",
		"usepam yes",
		"allowusers alice",
		"allowusers bob@10.0.0.0/8",
		"forcecommand /bin/LEAKCANARY",
		"authorizedkeyscommand /usr/bin/fetch --token LEAKCANARY %u",
		"authorizedkeyscommanduser nobody",
		"authorizedprincipalscommand none",
		"permitrootlogin \x01bad",
		"banner LEAKCANARY",
	}, "\n")
	res := parseSSHDT([]byte(out))
	assert.Len(t, res.effective, len(effectiveKeywords))
	assert.Equal(t, "yes", *res.effective["passwordauthentication"])
	assert.Equal(t, "alice bob@10.0.0.0/8", *res.effective["allowusers"])
	assert.Nil(t, res.effective["permitrootlogin"])
	assert.Nil(t, res.effective["denyusers"])
	assert.True(t, res.parseErr)
	require.NotNil(t, res.keysCommand)
	assert.Equal(t, "/usr/bin/fetch", *res.keysCommand.path)
	assert.Equal(t, "nobody", *res.keysCommand.user)
	assert.Nil(t, res.principalsCommand)
	assert.NotContains(t, fmt.Sprintf("%+v %+v", res.effective, *res.keysCommand), "LEAKCANARY")
	for _, v := range res.effective {
		if v != nil {
			assert.NotContains(t, *v, "LEAKCANARY")
		}
	}
}

func TestParseSSHDConfigMatch(t *testing.T) {
	src := mapSource{
		files: map[string]string{
			sshdConfigPath: "PasswordAuthentication no\nInclude conf.d/*.conf /etc/ssh/missing.conf\n" +
				"Match User deploy,!root Address 10.0.0.0/8\n  PasswordAuthentication Yes\n  AuthorizedKeysCommand /usr/bin/x --secret LEAKCANARY\n  AuthorizedKeysCommandUser nobody\n" +
				"Match Exec \"/bin/LEAKCANARY\"\n  PubkeyAuthentication no\n" +
				"Match all\n  X11Forwarding yes\n",
			"/etc/ssh/conf.d/10-a.conf": "Match LocalPort 2222\n  HostbasedAuthentication yes\n  ForceCommand LEAKCANARY\n",
			"/etc/ssh/conf.d/20-b.conf": "Include /etc/ssh/conf.d/20-b.conf\n",
		},
		dirs: map[string][]string{"/etc/ssh/conf.d": {"20-b.conf", "10-a.conf", "notes.txt", ".hidden.conf"}},
	}
	cfg := parseSSHDConfig(src)
	require.Len(t, cfg.blocks, 4)
	assert.Equal(t, "LocalPort 2222", *cfg.blocks[0].block.Criteria)
	assert.Equal(t, map[string]string{"hostbasedauthentication": "yes"}, cfg.blocks[0].block.Sets)
	assert.Equal(t, "User deploy,!root Address 10.0.0.0/8", *cfg.blocks[1].block.Criteria)
	assert.Equal(t, map[string]string{"passwordauthentication": "yes", "authorizedkeyscommand": "present"}, cfg.blocks[1].block.Sets)
	assert.Equal(t, "/usr/bin/x", *cfg.blocks[1].keysCommand.path)
	assert.Equal(t, "nobody", *cfg.blocks[1].keysCommand.user)
	assert.Nil(t, cfg.blocks[2].block.Criteria)
	assert.True(t, cfg.blocks[2].unsupported)
	assert.True(t, cfg.blocks[3].unsupported, "Match all is outside the re-emitted criteria")
	assert.True(t, cfg.reasons.has(reasonParseError), "an include cycle is a parse error")
	assert.False(t, cfg.readAll)
	out, err := encodeValue(cfg.blocks[0].block)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "LEAKCANARY")
	for _, b := range cfg.blocks {
		out, _ := encodeValue(b.block)
		assert.NotContains(t, string(out), "LEAKCANARY")
	}
}

func TestParseSSHDConfigIncludeDepth(t *testing.T) {
	files := map[string]string{sshdConfigPath: "Include /etc/ssh/d0\n"}
	for i := range maxIncludeDepth + 2 {
		files[fmt.Sprintf("/etc/ssh/d%d", i)] = fmt.Sprintf("Include /etc/ssh/d%d\n", i+1)
	}
	cfg := parseSSHDConfig(mapSource{files: files})
	assert.True(t, cfg.reasons.has(reasonLimitExceeded))
}

func TestParseSSHDArgs(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want sshdArgs
	}{
		{[]string{"/usr/sbin/sshd", "-D"}, sshdArgs{}},
		{[]string{"/usr/sbin/sshd", "-D", "-f", "/etc/ssh/other"}, sshdArgs{configPath: "/etc/ssh/other"}},
		{[]string{"/usr/sbin/sshd", "-Df/etc/ssh/x"}, sshdArgs{configPath: "/etc/ssh/x"}},
		{[]string{"/usr/sbin/sshd", "-o", "PasswordAuthentication=yes"}, sshdArgs{hasOverride: true}},
		{[]string{"/usr/sbin/sshd", "-Do", "X=y"}, sshdArgs{hasOverride: true}},
		{[]string{"/usr/sbin/sshd", "-Z"}, sshdArgs{hasOverride: true}},
		{[]string{"/usr/sbin/sshd", "stray"}, sshdArgs{hasOverride: true}},
		{[]string{"/usr/sbin/sshd", "-f"}, sshdArgs{hasOverride: true}},
	} {
		assert.Equal(t, tc.want, parseSSHDArgs(tc.argv), tc.argv)
	}
}

func TestParseProcStat(t *testing.T) {
	ps, ok := parseProcStat([]byte("812 (sshd) S 1 812 812 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 1000000 1000 100\n"))
	require.True(t, ok)
	assert.Equal(t, procStat{comm: "sshd", ppid: 1, startTick: 1000000}, ps)
	ps, ok = parseProcStat([]byte("9 (a) b) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1\n"))
	require.True(t, ok)
	assert.Equal(t, "a) b", ps.comm)
	_, ok = parseProcStat([]byte("garbage"))
	assert.False(t, ok)
}

func utmpRecord(typ uint16, user, line, host string, sec uint32) []byte {
	rec := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(rec[0:2], typ)
	copy(rec[8:40], line)
	copy(rec[44:76], user)
	copy(rec[76:332], host)
	binary.LittleEndian.PutUint32(rec[340:344], sec)
	return rec
}

func TestParseWtmp(t *testing.T) {
	var data []byte
	data = append(data, utmpRecord(utmpUserProcess, "alice", "pts/0", "10.0.0.1", 100)...)
	data = append(data, utmpRecord(utmpUserProcess, "alice", "pts/1", "LEAKCANARY host!", 200)...)
	data = append(data, utmpRecord(utmpUserProcess, "alice", "pts/2", "10.0.0.3", 150)...)
	data = append(data, utmpRecord(8, "alice", "pts/1", "", 300)...)
	data = append(data, utmpRecord(utmpUserProcess, "bad user", "pts/3", "", 400)...)
	data = append(data, 1, 2, 3)
	got := map[string]ptyRecord{}
	assert.Equal(t, 2, parseWtmp(data, got), "one invalid user, one partial record")
	require.Contains(t, got, "alice")
	assert.Equal(t, ptyRecord{time: 200, tty: ptr("pts/1")}, got["alice"], "a source outside the grammar is null")
	assert.Equal(t, &ptyLogin{Time: "1970-01-01T00:03:20Z", TTY: ptr("pts/1"), From: "wtmp"}, got["alice"].login("wtmp"))
}

func TestParseLastlog(t *testing.T) {
	rec := make([]byte, lastlogSize)
	_, ok := parseLastlog(rec)
	assert.False(t, ok, "zero time is never")
	binary.LittleEndian.PutUint32(rec[0:4], 1000)
	copy(rec[4:36], "tty1")
	copy(rec[36:292], "203.0.113.9")
	r, ok := parseLastlog(rec)
	require.True(t, ok)
	assert.Equal(t, ptyRecord{time: 1000, tty: ptr("tty1"), source: ptr("203.0.113.9")}, r)
	_, ok = parseLastlog(rec[:10])
	assert.False(t, ok)
}

func TestGrammar(t *testing.T) {
	assert.True(t, validFrom("10.0.0.0/8,!10.0.0.5,*.example.com,host?.lan,2001:db8::/32"))
	assert.False(t, validFrom("a b"))
	assert.False(t, validFrom("10.0.0.0/8,"))
	assert.True(t, validPath("/home/u/.ssh/authorized_keys"))
	for _, p := range []string{"/", "rel", "/a/../b", "/a//b", "/a/", "/a b", `/a"b`} {
		assert.False(t, validPath(p), p)
	}
	assert.True(t, validName("machine$"))
	assert.False(t, validName("-x"))
	assert.False(t, validName("$"))
}

func TestTrustUnicodeWhitespace(t *testing.T) {
	for _, input := range []string{"\r\r\n", "\v\n", " \n", " \n", "\u0085\n", "\f\n"} {
		for _, path := range []string{".rhosts", ".shosts", "hosts.equiv", ".k5login"} {
			t.Run(path+input, func(t *testing.T) {
				require.NotPanics(t, func() {
					if path == ".k5login" {
						e, u, limit := parseK5Login([]byte(input))
						assert.Empty(t, e)
						assert.Zero(t, u)
						assert.False(t, limit)
					} else {
						e, u, limit := parseHostsEquiv([]byte(input))
						assert.Empty(t, e)
						assert.Zero(t, u)
						assert.False(t, limit)
					}
				})
			})
		}
	}
}

func TestPrincipalGrammarsRejectShadow(t *testing.T) {
	line := "root:$y$j9T$abcdefghijklmnopqrstuv$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq:19000:0:99999:7:::"
	k, u, _ := parseK5Login([]byte(line + "\n"))
	assert.Empty(t, k)
	assert.Equal(t, 1, u)
	p, u, _, _ := parsePrincipalsFile([]byte(line + "\n"))
	assert.Empty(t, p)
	assert.Equal(t, 1, u)
	_, _, ok := parseKeyOptions([]byte(`principals="` + line + `" ssh-ed25519 ` + testEd0))
	assert.False(t, ok)
	assert.True(t, validK5Principal(strings.Repeat("a", 256)+"@"+strings.Repeat("b", 255)))
	assert.False(t, validK5Principal("a@b/c"))
	assert.True(t, validPrincipal("ops+a/b-c.d_e@realm"))
}

func TestTrustEntryCaps(t *testing.T) {
	var k5, hosts strings.Builder
	for i := 0; k5.Len() < maxReadBytes-16; i++ {
		fmt.Fprintf(&k5, "%x\n", i)
		fmt.Fprintf(&hosts, "h%x\n", i)
	}
	entries, _, limited := parseK5Login([]byte(k5.String()))
	assert.Len(t, entries, maxTrustEntries)
	assert.True(t, limited)
	hu, _, limited := parseHostsEquiv([]byte(hosts.String()))
	assert.Len(t, hu, maxTrustEntries)
	assert.True(t, limited)

}

func TestCommentsDropNonprintingBeforeCap(t *testing.T) {
	controls := "\u202e\u2066\u2067\u2068\u2069\u200b\u2028\u2029"
	comment, truncated := cleanComment([]byte(strings.Repeat(controls, 128) + strings.Repeat("x", 128)))
	require.NotNil(t, comment)
	assert.Equal(t, strings.Repeat("x", 128), *comment)
	assert.False(t, truncated)
}

func TestSSHDIncludeRestoresMatchState(t *testing.T) {
	src := mapSource{files: map[string]string{
		sshdConfigPath:   "Include /etc/ssh/extra\nPasswordAuthentication no\n",
		"/etc/ssh/extra": "Match Address 10.0.0.0/8\nPasswordAuthentication yes\n",
	}}
	cfg := parseSSHDConfig(src)
	require.Len(t, cfg.blocks, 1)
	assert.Equal(t, "yes", cfg.blocks[0].block.Sets["passwordauthentication"])
	assert.True(t, cfg.readAll)
}

func TestSSHDIncludeRestoresParentBlockAfterReallocation(t *testing.T) {
	cfg := parseSSHDConfig(mapSource{files: map[string]string{
		sshdConfigPath:   "Match User alice\n Include /etc/ssh/extra\n AuthorizedKeysCommand /usr/bin/keys\n",
		"/etc/ssh/extra": "Match Address 10.0.0.0/8\n PasswordAuthentication no\n",
	}})
	require.Len(t, cfg.blocks, 2)
	assert.True(t, cfg.blocks[0].hasKeysCmd)
	require.NotNil(t, cfg.blocks[0].keysCommand)
	assert.Equal(t, "/usr/bin/keys", *cfg.blocks[0].keysCommand.path)
}

func TestMatchBlockCount(t *testing.T) {
	var b strings.Builder
	for b.Len() < 1<<20-64 {
		b.WriteString("Match User a\nAuthorizedKeysCommand /bin/true\n")
	}
	cfg := parseSSHDConfig(mapSource{files: map[string]string{sshdConfigPath: b.String()}})
	assert.Len(t, cfg.blocks, 256)
	assert.True(t, cfg.reasons.has(reasonLimitExceeded))
	assert.True(t, cfg.readAll, "all files were read despite the record cap")
	assert.True(t, cfg.configIncomplete)
}

func TestGlobIncludeRestoresMatchStatePerFile(t *testing.T) {
	src := mapSource{files: map[string]string{
		sshdConfigPath:                     "Include /etc/ssh/sshd_config.d/*.conf\n",
		"/etc/ssh/sshd_config.d/10-a.conf": "Match User bob\n X11Forwarding no\n",
		"/etc/ssh/sshd_config.d/20-b.conf": "PasswordAuthentication yes\nAuthorizedKeysCommand /usr/bin/x\nAuthorizedKeysCommandUser nobody\n",
	}, dirs: map[string][]string{"/etc/ssh/sshd_config.d": {"10-a.conf", "20-b.conf"}}}
	cfg := parseSSHDConfig(src)
	require.Len(t, cfg.blocks, 1)
	assert.NotContains(t, cfg.blocks[0].block.Sets, "passwordauthentication")
	assert.False(t, cfg.blocks[0].hasKeysCmd)
}

func TestNBSPBeforeCommentIsParsed(t *testing.T) {
	pw := parsePasswd([]byte("root:x:0:0:root:/root:/bin/bash\n\u00a0#x:x:0:0::/root:/bin/bash\n"))
	assert.Len(t, pw.entries, 1)
	assert.Equal(t, 1, pw.unparsed)
	gr := parseGroup([]byte("\u00a0#x:x:0:\n"))
	assert.Equal(t, 1, gr.unparsed)
	_, unparsed := parseShadow([]byte("\u00a0#x:!:1::::::\n"))
	assert.Equal(t, 1, unparsed)
	for _, prefix := range []string{"", " ", "\t", "\v", "\f", "\r"} {
		assert.True(t, isBlankOrComment([]byte(prefix+"# comment")))
	}
	assert.True(t, isBlankOrComment([]byte("\u00a0")))
}

func TestSSHDQuotedArgumentPreservesEscapedSpace(t *testing.T) {
	for _, tc := range []struct {
		input, want string
	}{
		{`"a\ b"`, `a\ b`},
		{`'a\ b'`, `a\ b`},
		{`a\ b`, `a b`},
	} {
		t.Run(tc.input, func(t *testing.T) {
			args, ok := splitArgs(tc.input)
			require.True(t, ok)
			assert.Equal(t, []string{tc.want}, args)
		})
	}
}

func TestMatchFirstValueWins(t *testing.T) {
	cfg := parseSSHDConfig(mapSource{files: map[string]string{sshdConfigPath: "Match User alice\nPasswordAuthentication yes\nPasswordAuthentication no\nAuthorizedKeysCommand /bin/first\nAuthorizedKeysCommand /bin/second\nAuthorizedKeysCommandUser root\nAuthorizedKeysCommandUser nobody\n"}})
	require.Len(t, cfg.blocks, 1)
	b := cfg.blocks[0]
	assert.Equal(t, "yes", b.block.Sets["passwordauthentication"])
	require.NotNil(t, b.keysCommand)
	assert.Equal(t, "/bin/first", *b.keysCommand.path)
	assert.Equal(t, "root", *b.keysCommand.user)
}
func TestSSHDArgumentCommentsAndQuotes(t *testing.T) {
	kw, args, ok := splitConfigLine([]byte("PasswordAuthentication yes # note"))
	require.True(t, ok)
	assert.Equal(t, "passwordauthentication", kw)
	assert.Equal(t, []string{"yes"}, args)
	_, args, ok = splitConfigLine([]byte("Match User alice # note"))
	require.True(t, ok)
	assert.False(t, newMatchBlock(args).unsupported)
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"'one two'", []string{"one two"}},
		{`"one two"`, []string{"one two"}},
		{`one\ two a\"b c\\d x#y # end`, []string{"one two", `a"b`, `c\d`, "x#y"}},
	} {
		got, ok := splitArgs(tc.in)
		assert.True(t, ok)
		assert.Equal(t, tc.want, got)
	}
}
