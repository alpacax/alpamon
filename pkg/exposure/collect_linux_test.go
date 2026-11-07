//go:build linux

package exposure

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"

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

func TestBudgetRecoversParserPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		c := newCollector(collectorOptions{budget: categoryBudget})
		data, ok := runBudget(context.Background(), c, catKeys, func(context.Context) keysData { panic("LEAKCANARY panic contents") })
		require.True(t, ok)
		assert.True(t, data.reasons.has(reasonParseError))
		b := assembly{accOK: true, acc: accountsData{usable: true, entries: []passwdEntry{{name: "u", home: "/home/u"}}}, sshdOK: true, sshd: sshdData{t: &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys")}}}, keysOK: ok, keys: data}
		r := b.report()
		require.Len(t, r.Accounts, 1)
		require.Len(t, r.Accounts[0].KeyFiles, 1)
		assert.False(t, r.Accounts[0].KeyFiles[0].Complete)
		assert.Contains(t, r.Accounts[0].KeyFiles[0].Reasons, reasonParseError)
		assert.Contains(t, r.Categories[catKeys].Reasons, reasonParseError)
		assert.NotContains(t, logs.String(), "LEAKCANARY")
		assert.Contains(t, logs.String(), "Exposure category parser panicked.")
	})
}

func TestAccountDeadlineLeavesOtherAccountsComplete(t *testing.T) {
	root, owners := attackRoot(t)
	for _, user := range []string{"u", "v"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "home", user, ".ssh"), 0o755))
		p := "/home/" + user + "/.ssh/authorized_keys"
		owners[p] = 1001
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("ssh-ed25519 "+testEd0+"\n"), 0o644))
	}
	release := make(chan struct{})
	finished := make(chan struct{})
	testHookRead = func(p string) {
		if p == "/home/u/.ssh/authorized_keys" {
			<-release
			close(finished)
		}
	}
	defer func() { testHookRead = nil }()
	c := newCollector(collectorOptions{root: root, budget: categoryBudget, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }})
	st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys"), "authorizedprincipalsfile": ptr("none"), "trustedusercakeys": ptr("none")}}
	accounts := []passwdEntry{{name: "u", uid: 1001, home: "/home/u"}, {name: "v", uid: 1001, home: "/home/v"}}
	d := c.readKeysBudget(context.Background(), accounts, st, sshdConfig{})
	require.Len(t, d.byUser["u"].files, 1)
	assert.Equal(t, statusTimeout, d.byUser["u"].files[0].Status)
	require.Len(t, d.byUser["v"].files, 1)
	assert.True(t, d.byUser["v"].files[0].Complete)
	assert.Len(t, d.byUser["v"].files[0].Keys, 1)
	// A repeated read must skip the already occupied account slot.
	d = c.readKeysBudget(context.Background(), accounts, st, sshdConfig{})
	assert.Equal(t, statusTimeout, d.byUser["u"].files[0].Status)
	assert.True(t, d.byUser["v"].files[0].Complete)
	close(release)
	<-finished
	// Wait for the pinned reader to close before the fixture and hooks go away.
	c.accountMu.Lock()
	busy := c.accountCount
	c.accountMu.Unlock()
	for busy != 0 {
		runtime.Gosched()
		c.accountMu.Lock()
		busy = c.accountCount
		c.accountMu.Unlock()
	}
}

func TestAccountWorkerBoundsAcrossReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newCollector(collectorOptions{budget: categoryBudget})
		release := make(chan struct{})
		var started atomic.Int32
		fn := func() int { started.Add(1); <-release; return 1 }
		for i := 0; i < maxAccountWorkers; i++ {
			_, reason := runAccountBudget(context.Background(), c, catKeys, fmt.Sprint(i), fn)
			assert.Equal(t, reasonTimeout, reason)
		}
		for range 3 {
			for i := 0; i <= maxAccountWorkers; i++ {
				_, reason := runAccountBudget(context.Background(), c, catKeys, fmt.Sprint(i), fn)
				assert.Equal(t, reasonTimeout, reason)
			}
		}
		assert.Equal(t, int32(maxAccountWorkers), started.Load())
		c.accountMu.Lock()
		assert.Equal(t, maxAccountWorkers, c.accountCount)
		c.accountMu.Unlock()
		close(release)
		synctest.Wait()
		_, reason := runAccountBudget(context.Background(), c, catKeys, "fresh", func() int { return 1 })
		assert.Empty(t, reason)
	})
}

func TestUnusedAccountSourcesIgnoreOccupiedSlots(t *testing.T) {
	root, owners := attackRoot(t)
	c := newCollector(collectorOptions{root: root, budget: categoryBudget, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }})
	c.accountCount = maxAccountWorkers
	st := &sshdT{effective: map[string]*string{"authorizedprincipalsfile": ptr("none"), "trustedusercakeys": ptr("none")}}
	accounts := []passwdEntry{{name: "u", uid: 1001, home: "/home/u"}}
	assert.Empty(t, c.readCertsBudget(context.Background(), accounts, st, sshdConfig{}).reasons)
	assert.Empty(t, c.readTrustBudget(context.Background(), accounts, st, sshdConfig{}).reasons)
}

func TestSudoAllKeepsCategoryCovered(t *testing.T) {
	p := readSudoPolicy(mapSource{files: map[string]string{sudoersPath: "ALL ALL=(ALL) NOPASSWD: ALL\n"}}, "host")
	b := assembly{accOK: true, acc: accountsData{usable: true, entries: []passwdEntry{{name: "u"}, {name: "root"}}}, sudoOK: true, sudo: p}
	assert.Equal(t, Coverage{Status: coverageCovered, Reasons: []string{}}, b.report().Categories[catSudo])
}

func TestCategoryPanicKeepsSystemSourceEnvelopes(t *testing.T) {
	st := &sshdT{effective: map[string]*string{"trustedusercakeys": ptr("/etc/ssh/ca"), "hostbasedauthentication": ptr("yes")}}
	b := assembly{accOK: true, acc: accountsData{usable: true}, sshdOK: true, sshd: sshdData{t: st}, certsOK: true, certs: categoryFailure[certsData](reasonParseError), trustOK: true, trust: categoryFailure[trustData](reasonParseError)}
	r := b.report()
	require.NotNil(t, r.UserCA)
	assert.False(t, r.UserCA.Complete)
	assert.Equal(t, []string{reasonParseError}, r.UserCA.Reasons)
	require.Len(t, r.SystemTrust, 2)
	for _, s := range r.SystemTrust {
		assert.False(t, s.Complete)
		assert.Equal(t, []string{reasonParseError}, s.Reasons)
	}
}

func TestFailedKeySourcesStaySortedAndUnique(t *testing.T) {
	st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/z .ssh/a %h/.ssh/z")}}
	failed := failedAccountKeys(passwdEntry{name: "u", home: "/home/u"}, st, reasonTimeout)
	require.Len(t, failed.files, 2)
	assert.Equal(t, "/home/u/.ssh/a", failed.files[0].Path)
	assert.Equal(t, "/home/u/.ssh/z", failed.files[1].Path)
}

func TestTrustFileEntryCapMarksSourceIncomplete(t *testing.T) {
	root, owners := attackRoot(t)
	var data strings.Builder
	for i := 0; data.Len() < maxReadBytes-16; i++ {
		fmt.Fprintf(&data, "%x\n", i)
	}
	data.WriteString(strings.Repeat("\n", maxReadBytes-data.Len()))
	p := "/home/u/.k5login"
	owners[p] = 1001
	require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(data.String()), 0o644))
	fs := readerFor(t, root, owners)
	d := readTrust(fs, systemFiles{f: fs}, []passwdEntry{{name: "u", uid: 1001, home: "/home/u"}}, &sshdT{effective: map[string]*string{"gssapiauthentication": ptr("yes")}}, sshdConfig{})
	require.Len(t, d.files["u"], 1)
	s := d.files["u"][0]
	assert.Len(t, s.Entries, maxTrustEntries)
	assert.False(t, s.Complete)
	assert.Contains(t, s.Reasons, reasonLimitExceeded)
}

func TestDuplicateAccountSources(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		for _, tc := range []struct {
			name, path, duplicate, category string
		}{
			{"passwd", "etc/passwd", "ubuntu:hash:2002:27::/home/dropped:/bin/sh\n", catAccounts},
			{"shadow", "etc/shadow", "ubuntu::1:0:99999:7:1:2:\n", catPasswords},
			{"group", "etc/group", "sudo:x:2002:root\n", catAccounts},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := filepath.Join(fixturesDir, "hosts", "ubuntu-default")
				spec := loadCase(t, dir)
				root, proc := buildHost(t, dir, spec)
				path := filepath.Join(root, tc.path)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, append(data, tc.duplicate...), 0o644))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "home/dropped/.ssh"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(root, "home/dropped/.ssh/authorized_keys"), []byte("ssh-ed25519 "+testEd1+" dropped-key\n"), 0o644))
				opens := recordOpens(t, nil)
				opts := caseOptions(t, dir, spec, root, proc)
				// Enable home trust reads so the open recorder also covers them.
				runSSHD := opts.runSSHD
				opts.runSSHD = func(ctx context.Context) sshdRun {
					run := runSSHD(ctx)
					run.out = append(run.out, "\ngssapiauthentication yes\n"...)
					return run
				}
				r := newCollector(opts).collect(context.Background())
				assert.Contains(t, r.Categories[tc.category].Reasons, reasonParseError)
				assert.NotEqual(t, coverageCovered, r.Categories[tc.category].Status)
				var ubuntu []Account
				for _, a := range r.Accounts {
					if a.Username == "ubuntu" {
						ubuntu = append(ubuntu, a)
					}
				}
				require.Len(t, ubuntu, 1)
				assert.Equal(t, uint32(1000), ubuntu[0].UID)
				assert.Equal(t, ptr("/bin/bash"), ubuntu[0].Shell)
				assert.Contains(t, ubuntu[0].Groups, "sudo")
				assert.Equal(t, passwordSet, ubuntu[0].Shadow.PasswordState)
				assert.Equal(t, ptr(int64(20123)), ubuntu[0].Shadow.LastChangeDays)
				body, err := finalize(r)
				require.NoError(t, err)
				assert.NotContains(t, string(body), "/home/dropped")
				assert.NotContains(t, string(body), "dropped-key")
				assert.Contains(t, opens(), "/home/ubuntu/.ssh/authorized_keys")
				assert.Contains(t, opens(), "/home/ubuntu/.k5login")
				for _, opened := range opens() {
					assert.False(t, opened == "/home/dropped" || strings.HasPrefix(opened, "/home/dropped/"), opened)
				}
			})
		}
	})
}
