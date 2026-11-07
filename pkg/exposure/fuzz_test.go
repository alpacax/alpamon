package exposure

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"unicode/utf8"
)

// Fuzz targets, one per parser. Each appends input that carries a canary in
// a place the report must never copy, then checks: no panic, every cap held,
// and the canary absent from what the parser returns. An input that itself
// contains the canary is skipped, since a comment, say, may carry it legally.

const fuzzCanary = "FUZZCANARY"

func skipCanary(t *testing.T, data []byte) {
	if bytes.Contains(data, []byte(fuzzCanary)) {
		t.Skip()
	}
}

func assertNoCanary(t *testing.T, v any) {
	t.Helper()
	out, err := encodeValue(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(out, []byte(fuzzCanary)) {
		t.Fatalf("canary emitted: %s", out)
	}
	if !utf8.Valid(out) {
		t.Fatalf("invalid UTF-8 emitted")
	}
}

func FuzzShadow(f *testing.F) {
	f.Add([]byte("root:*:20000:0:99999:7:::\nalice:$6$salt$hash:1:0:99999:7:30:40:\n"))
	f.Add([]byte("x:!!:::::::\n:::::::::\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(append([]byte("canary:$6$"+fuzzCanary+"$hash:1::::::\n"), data...), "\ncanary2:!"+fuzzCanary+":1::::::\n"...)
		infos, _ := parseShadow(data)
		if s := fmt.Sprintf("%+v", infos); strings.Contains(s, fuzzCanary) {
			t.Fatalf("canary kept: %s", s)
		}
		for _, info := range infos {
			switch info.state {
			case passwordEmpty, passwordNone, passwordLocked, passwordSet, passwordUnknown:
			default:
				t.Fatalf("state %q", info.state)
			}
		}
	})
}

func FuzzAuthorizedKeys(f *testing.F) {
	f.Add([]byte("ssh-ed25519 " + testEd0 + " a\n"))
	f.Add([]byte(`from="10.0.0.0/8",no-pty ssh-ed25519 ` + testEd1 + " b\n"))
	f.Add([]byte(`cert-authority,principals="a,b" ssh-ed25519 ` + testEd0 + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\ncommand=\""+fuzzCanary+"\",environment=\"K="+fuzzCanary+"\" ssh-ed25519 "+testEd0+" c\nssh-ed25519 AAAA"+fuzzCanary+"\n"...)
		budget := maxKeysPerAccount
		res := parseAuthorizedKeys(data, &budget)
		assertNoCanary(t, res.keys)
		if budget < 0 {
			t.Fatal("key budget overrun")
		}
		for _, k := range res.keys {
			for _, a := range k.Authorizations {
				if a.Comment != nil && utf8.RuneCountInString(*a.Comment) > maxCommentRunes {
					t.Fatal("comment over the cap")
				}
				if a.From != nil && len(*a.From) > maxFromBytes {
					t.Fatal("from= over the cap")
				}
				if len(a.Principals) > maxPrincipals {
					t.Fatal("principals over the cap")
				}
				for _, o := range a.Options {
					if _, ok := keyOptionTakesValue[o]; !ok {
						t.Fatalf("unknown option %q emitted", o)
					}
				}
			}
		}
	})
}

func FuzzPrincipals(f *testing.F) {
	f.Add([]byte("deploy\nfrom=\"10.0.0.1\" ops\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\ncommand=\""+fuzzCanary+"\" alice\n"...)
		entries, _, _, _ := parsePrincipalsFile(data)
		assertNoCanary(t, entries)
		if len(entries) > maxPrincipalEntries {
			t.Fatal("entries over the cap")
		}
	})
}

func FuzzSudoers(f *testing.F) {
	f.Add([]byte("root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) NOPASSWD: ALL\n"))
	f.Add([]byte("User_Alias A = alice, %ops\nCmnd_Alias C = /bin/a x, /bin/b\nA ALL = (root) C\n"))
	f.Add([]byte("Defaults:alice targetpw\nalice ALL = ALL, !/bin/su\n@includedir /etc/sudoers.d\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\n\nalice ALL = /bin/x "+fuzzCanary+"\nbob ALL = ALL, !/bin/su "+fuzzCanary+"\n"...)
		pol := readSudoPolicy(mapSource{files: map[string]string{sudoersPath: string(data)}, dirs: map[string][]string{}}, "h")
		for _, u := range []string{"alice", "bob", "root"} {
			got := pol.forAccount(u, func(string) bool { return true })
			assertNoCanary(t, got)
			for _, g := range got.Grants {
				if len(g.CommandPaths) > maxCommandPaths {
					t.Fatal("command paths over the cap")
				}
			}
		}
	})
}

func FuzzSSHDT(f *testing.F) {
	f.Add([]byte("passwordauthentication no\nusepam yes\nallowusers a\nallowusers b\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\nforcecommand "+fuzzCanary+"\nauthorizedkeyscommand /usr/bin/k "+fuzzCanary+"\nbanner "+fuzzCanary+"\n"...)
		res := parseSSHDT(data)
		if len(res.effective) != len(effectiveKeywords) {
			t.Fatal("effective holds other keywords")
		}
		assertNoCanary(t, res.effective)
		for _, c := range []*providerCommand{res.keysCommand, res.principalsCommand} {
			if c != nil && c.path != nil && strings.Contains(*c.path, fuzzCanary) {
				t.Fatal("provider argument emitted")
			}
		}
		for _, v := range res.effective {
			if v != nil && len(*v) > maxEffectiveValueLen {
				t.Fatal("value over the cap")
			}
		}
	})
}

func FuzzMatch(f *testing.F) {
	f.Add([]byte("Match User a Address 10.0.0.0/8\n PasswordAuthentication yes\nInclude /etc/ssh/x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		cfg := append(data, "\nMatch Exec \""+fuzzCanary+"\"\n ForceCommand "+fuzzCanary+"\nMatch User x\n AuthorizedKeysCommand /bin/k "+fuzzCanary+"\n"...)
		res := parseSSHDConfig(mapSource{files: map[string]string{sshdConfigPath: string(cfg), "/etc/ssh/x": string(data)}})
		for _, b := range res.blocks {
			assertNoCanary(t, b.block)
			if b.keysCommand != nil && b.keysCommand.path != nil && strings.Contains(*b.keysCommand.path, fuzzCanary) {
				t.Fatal("provider argument emitted")
			}
		}
	})
}

func FuzzWtmp(f *testing.F) {
	f.Add(utmpRecord(utmpUserProcess, "alice", "pts/0", "10.0.0.1", 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(utmpRecord(utmpUserProcess, "alice", "pts/0", fuzzCanary+" !", 1), data...)
		got := map[string]ptyRecord{}
		parseWtmp(data, got)
		for user, r := range got {
			if !validName(user) {
				t.Fatalf("user %q", user)
			}
			assertNoCanary(t, *r.login("wtmp"))
			if r.tty != nil && !validTTY(*r.tty) || r.source != nil && !validHostname(*r.source) {
				t.Fatal("field outside its grammar")
			}
		}
	})
}

func FuzzLastlog(f *testing.F) {
	f.Add(make([]byte, lastlogSize))
	f.Fuzz(func(t *testing.T, rec []byte) {
		r, ok := parseLastlog(rec)
		if !ok {
			return
		}
		if r.tty != nil && !validTTY(*r.tty) || r.source != nil && !validHostname(*r.source) {
			t.Fatal("field outside its grammar")
		}
	})
}

func FuzzHostsEquiv(f *testing.F) {
	f.Add([]byte("host.example alice\n\v\n \n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\n"+fuzzCanary+":secret user\n"...)
		entries, _, _ := parseHostsEquiv(data)
		assertNoCanary(t, entries)
		require.LessOrEqual(t, len(entries), maxTrustEntries)
		for _, e := range entries {
			assert.True(t, validHostname(e.Host))
			if e.User != nil {
				assert.True(t, validName(*e.User))
			}
		}
	})
}

func FuzzK5Login(f *testing.F) {
	f.Add([]byte("alice@EXAMPLE.COM\n\r\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\nroot:$y$"+fuzzCanary+":19000:0:99999:7:::\n"...)
		entries, _, _ := parseK5Login(data)
		assertNoCanary(t, entries)
		require.LessOrEqual(t, len(entries), maxTrustEntries)
		for _, e := range entries {
			require.NotNil(t, e.Principal)
			assert.True(t, validK5Principal(*e.Principal))
		}
	})
}

func FuzzPasswd(f *testing.F) {
	f.Add([]byte("alice:x:1000:1000::/home/alice:/bin/sh\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\ncanary:"+fuzzCanary+":1:1:"+fuzzCanary+":/home/canary:/bin/sh\n"...)
		result := parsePasswd(data)
		require.LessOrEqual(t, len(result.entries), maxAccounts)
		assert.NotContains(t, fmt.Sprintf("%+v", result.entries), fuzzCanary)
		for _, e := range result.entries {
			assert.True(t, validName(e.name))
			assert.True(t, e.home == "" || e.home == "/" || validPath(e.home))
			assert.True(t, e.shell == "" || validPath(e.shell))
		}
	})
}

func FuzzGroup(f *testing.F) {
	f.Add([]byte("ops:x:1000:alice,bob\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\ncanary:"+fuzzCanary+":1:alice\n"...)
		result := parseGroup(data)
		assert.NotContains(t, fmt.Sprintf("%+v", result.groups), fuzzCanary)
		for _, e := range result.groups {
			assert.True(t, validName(e.name))
			for _, m := range e.members {
				assert.True(t, validName(m))
			}
		}
	})
}

func FuzzNSSwitch(f *testing.F) {
	f.Add([]byte("passwd: files sss [NOTFOUND=return]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		skipCanary(t, data)
		data = append(data, "\npasswd: files ["+fuzzCanary+"=return]\n"...)
		result, _ := parseNSSwitch(data)
		assertNoCanary(t, result)
		for _, modules := range result {
			for _, m := range modules {
				assert.True(t, validName(m))
			}
		}
	})
}
