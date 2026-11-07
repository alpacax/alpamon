//go:build linux

package exposure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemdNSSSources(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			files      []string
			unreadable string
			foreign    string
			passwd     string
			group      string
			accounts   bool
			groups     bool
		}{
			{name: "DynamicUser only"},
			{name: "unrelated entries", files: []string{"var/lib/systemd/home/alice.home.bak", "etc/userdb/alice.user.bak", "etc/userdb/alice.group.bak"}},
			{name: "wrong directory", files: []string{"var/lib/systemd/home/alice.user", "var/lib/systemd/home/alice.group", "etc/userdb/alice.home"}},
			{name: "homed", files: []string{"var/lib/systemd/home/alice.home"}, accounts: true, groups: true},
			{name: "userdb account", files: []string{"etc/userdb/alice.user"}, accounts: true},
			{name: "userdb group", files: []string{"etc/userdb/alice.group"}, groups: true},
			{name: "both userdb records", files: []string{"etc/userdb/alice.user", "etc/userdb/alice.group"}, accounts: true, groups: true},
			{name: "unreadable homes", unreadable: "/var/lib/systemd/home", accounts: true, groups: true},
			{name: "unreadable userdb", unreadable: "/etc/userdb", accounts: true, groups: true},
			{name: "non-root userdb", files: []string{"etc/userdb/alice.user"}, foreign: "/etc/userdb", accounts: true, groups: true},
			{name: "passwd only", files: []string{"var/lib/systemd/home/alice.home"}, passwd: "files systemd", group: "files", accounts: true},
			{name: "group only", files: []string{"var/lib/systemd/home/alice.home"}, passwd: "files", group: "files systemd", groups: true},
			{name: "unused sources are not inspected", passwd: "files", group: "files", unreadable: "/etc/userdb"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				root, owners := attackRoot(t)
				passwd, group := tc.passwd, tc.group
				if passwd == "" {
					passwd, group = "files systemd", "files systemd"
				}
				require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(root, "etc/nsswitch.conf"), []byte("passwd: "+passwd+"\ngroup: "+group+"\n"), 0o644))
				for _, name := range tc.files {
					require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755))
					require.NoError(t, os.WriteFile(filepath.Join(root, name), nil, 0o644))
				}
				if tc.foreign != "" {
					owners[tc.foreign] = 1001
				}
				var denied []string
				if tc.unreadable != "" {
					require.NoError(t, os.MkdirAll(filepath.Join(root, tc.unreadable), 0o755))
					denied = []string{tc.unreadable}
				}
				opens := recordOpens(t, denied)
				d := readAccounts(systemFiles{f: readerFor(t, root, owners)})
				b := assembly{acc: d, accOK: true}
				r := b.report()
				want := []External{}
				if tc.accounts {
					want = append(want, External{Kind: externalNSSAccounts, Scope: "global", Sources: []string{"systemd"}})
				}
				if tc.groups {
					want = append(want, External{Kind: externalNSSGroups, Scope: "global", Sources: []string{"systemd"}})
				}
				assert.Equal(t, want, r.External)
				assert.Equal(t, (tc.unreadable != "" || tc.foreign != "") && (tc.accounts || tc.groups), d.reasons.has(reasonFileUnreadable))
				if passwd == "files" && group == "files" {
					assert.NotContains(t, opens(), "/etc/userdb")
					assert.NotContains(t, opens(), "/var/lib/systemd/home")
				}
			})
		}
	})
}

func TestOtherNSSModulesUnchanged(t *testing.T) {
	for _, systemd := range []bool{false, true} {
		assert.Equal(t, []string{"cache", "compat", "ldap", "myhostname", "mymachines", "nis", "resolve", "sss", "unknown", "winbind"},
			nonFilesModules([]string{"files", "sss", "ldap", "winbind", "nis", "compat", "cache", "myhostname", "resolve", "mymachines", "unknown", "sss"}, systemd))
	}
}
