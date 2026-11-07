//go:build linux

package exposure

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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
			{name: "unrelated entries", files: []string{"var/lib/systemd/home/alice.identity.bak", "etc/userdb/alice.user.bak", "etc/userdb/alice.group.bak"}},
			{name: "wrong directory", files: []string{"var/lib/systemd/home/alice.user", "var/lib/systemd/home/alice.group", "etc/userdb/alice.identity"}},
			{name: "homed", files: []string{"var/lib/systemd/home/alice.identity"}, accounts: true, groups: true},
			{name: "userdb account", files: []string{"etc/userdb/alice.user"}, accounts: true},
			{name: "userdb group", files: []string{"etc/userdb/alice.group"}, groups: true},
			{name: "both userdb records", files: []string{"etc/userdb/alice.user", "etc/userdb/alice.group"}, accounts: true, groups: true},
			{name: "unreadable homes", unreadable: "/var/lib/systemd/home", accounts: true, groups: true},
			{name: "unreadable userdb", unreadable: "/etc/userdb", accounts: true, groups: true},
			{name: "non-root userdb", files: []string{"etc/userdb/alice.user"}, foreign: "/etc/userdb", accounts: true, groups: true},
			{name: "passwd only", files: []string{"var/lib/systemd/home/alice.identity"}, passwd: "files systemd", group: "files", accounts: true},
			{name: "group only", files: []string{"var/lib/systemd/home/alice.identity"}, passwd: "files", group: "files systemd", groups: true},
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
	busy := len(c.accountBusy)
	c.accountMu.Unlock()
	for busy != 0 {
		runtime.Gosched()
		c.accountMu.Lock()
		busy = len(c.accountBusy)
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
			_, reason, _ := runAccountBudget(context.Background(), c, catKeys, fmt.Sprint(i), fn)
			assert.Equal(t, reasonTimeout, reason)
		}
		for range 3 {
			for i := 0; i < maxAccountWorkers+maxConcurrentAccounts; i++ {
				_, reason, _ := runAccountBudget(context.Background(), c, catKeys, fmt.Sprint(i), fn)
				assert.Equal(t, reasonTimeout, reason)
			}
		}
		assert.Equal(t, int32(maxAccountWorkers+maxConcurrentAccounts), started.Load())
		c.accountMu.Lock()
		assert.Equal(t, maxAccountWorkers, c.accountCount)
		c.accountMu.Unlock()
		close(release)
		synctest.Wait()
		_, reason, _ := runAccountBudget(context.Background(), c, catKeys, "fresh", func() int { return 1 })
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

func waitAccountWorkers(c *collector) {
	for {
		c.accountMu.Lock()
		count := len(c.accountBusy)
		c.accountMu.Unlock()
		if count == 0 {
			return
		}
		runtime.Gosched()
	}
}

func TestSixHungHomesKeepHealthyAccounts(t *testing.T) {
	root, owners := attackRoot(t)
	var accounts []passwdEntry
	for i := 0; i < 8; i++ {
		user := fmt.Sprintf("u%d", i)
		require.NoError(t, os.MkdirAll(filepath.Join(root, "home", user, ".ssh"), 0o755))
		p := "/home/" + user + "/.ssh/authorized_keys"
		owners[p] = 1001
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("ssh-ed25519 "+testEd0+"\n"), 0o644))
		accounts = append(accounts, passwdEntry{name: user, uid: 1001, home: "/home/" + user})
	}
	release := make(chan struct{})
	testHookRead = func(p string) {
		if strings.HasPrefix(p, "/home/u") && p[7] < '6' {
			<-release
		}
	}
	c := newCollector(collectorOptions{root: root, budget: categoryBudget, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }})
	defer func() { close(release); waitAccountWorkers(c); testHookRead = nil }()
	st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys")}}
	d, ok := runBudget(context.Background(), c, catKeys, func(ctx context.Context) keysData { return c.readKeysBudget(ctx, accounts, st, sshdConfig{}) })
	require.True(t, ok)
	assert.Equal(t, coveragePartial, coverageOf(categoryState{usable: d.usable, reasons: d.reasons}).Status)
	assert.True(t, d.reasons.has(reasonTimeout))
	for i, a := range accounts {
		files := d.byUser[a.name].files
		require.Len(t, files, 1)
		assert.Equal(t, "/home/"+a.name+"/.ssh/authorized_keys", files[0].Path)
		if i < 6 {
			assert.Equal(t, statusTimeout, files[0].Status)
		} else {
			assert.True(t, files[0].Complete)
			assert.Len(t, files[0].Keys, 1)
		}
	}
}

func TestAllHungHomesReturnPartialWithoutWorkerGrowth(t *testing.T) {
	for _, cat := range []string{catKeys, catCertificates, catTrust} {
		t.Run(cat, func(t *testing.T) {
			root, owners := attackRoot(t)
			accounts := []passwdEntry{}
			for i := 0; i < 8; i++ {
				user := fmt.Sprintf("u%d", i)
				home := "/home/" + user
				require.NoError(t, os.MkdirAll(filepath.Join(root, home, ".ssh"), 0o755))
				for _, name := range []string{".ssh/authorized_keys", ".ssh/principals", ".k5login"} {
					p := home + "/" + name
					owners[p] = 1001
					require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("alice\n"), 0o644))
				}
				accounts = append(accounts, passwdEntry{name: user, uid: 1001, home: home})
			}
			release := make(chan struct{})
			testHookRead = func(p string) {
				if strings.HasPrefix(p, "/home/") {
					<-release
				}
			}
			c := newCollector(collectorOptions{root: root, budget: 750 * time.Millisecond, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }})
			defer func() { close(release); waitAccountWorkers(c); testHookRead = nil }()
			st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys"), "authorizedprincipalsfile": ptr(".ssh/principals"), "trustedusercakeys": ptr("none"), "gssapiauthentication": ptr("yes")}}
			for read := 0; read < 5; read++ {
				var reasons reasonSet
				var usable bool
				var files = map[string][]Envelope{}
				switch cat {
				case catKeys:
					d, ok := runBudget(context.Background(), c, cat, func(ctx context.Context) keysData { return c.readKeysBudget(ctx, accounts, st, sshdConfig{}) })
					require.True(t, ok)
					reasons, usable = d.reasons, d.usable
					for user, ak := range d.byUser {
						for _, f := range ak.files {
							files[user] = append(files[user], f.Envelope)
						}
					}
				case catCertificates:
					d, ok := runBudget(context.Background(), c, cat, func(ctx context.Context) certsData { return c.readCertsBudget(ctx, accounts, st, sshdConfig{}) })
					require.True(t, ok)
					reasons, usable = d.reasons, d.usable
					for user, fs := range d.principals {
						for _, f := range fs {
							files[user] = append(files[user], f.Envelope)
						}
					}
				case catTrust:
					d, ok := runBudget(context.Background(), c, cat, func(ctx context.Context) trustData { return c.readTrustBudget(ctx, accounts, st, sshdConfig{}) })
					require.True(t, ok)
					reasons, usable = d.reasons, d.usable
					for user, fs := range d.files {
						for _, f := range fs {
							files[user] = append(files[user], f.Envelope)
						}
					}
				}
				assert.Equal(t, Coverage{Status: coveragePartial, Reasons: []string{reasonTimeout}}, coverageOf(categoryState{usable: usable, reasons: reasons}))
				for _, a := range accounts {
					require.Len(t, files[a.name], 1)
					assert.Equal(t, statusTimeout, files[a.name][0].Status)
					assert.True(t, strings.HasPrefix(files[a.name][0].Path, a.home+"/"))
				}
				c.accountMu.Lock()
				assert.LessOrEqual(t, c.accountCount, maxAccountWorkers)
				if read >= 1 {
					assert.Equal(t, 8, c.accountCount, "occupied account slots must not grow on subsequent reads")
				}
				c.accountMu.Unlock()
			}
		})
	}
}

func TestAccountConcurrencyAndCategoryReturnMargin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newCollector(collectorOptions{budget: categoryBudget})
		accounts := []passwdEntry{}
		for i := 0; i < 24; i++ {
			accounts = append(accounts, passwdEntry{name: fmt.Sprint(i)})
		}
		release := make(chan struct{})
		var active, maximum atomic.Int32
		results := map[string]string{}
		ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
		defer cancel()
		start := time.Now()
		done := make(chan struct{})
		go func() {
			defer close(done)
			readAccountResults(ctx, c, catKeys, accounts, func(passwdEntry) int {
				n := active.Add(1)
				for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
				}
				<-release
				active.Add(-1)
				return 1
			}, func(a passwdEntry, _ int, reason string) { results[a.name] = reason })
		}()
		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(4), active.Load())
		<-done
		assert.Equal(t, 3250*time.Millisecond, time.Since(start))
		require.Len(t, results, 24)
		for _, reason := range results {
			assert.Equal(t, reasonTimeout, reason)
		}
		// Four attempts at a time, with timed-out workers retained up to 16.
		assert.Equal(t, int32(8), maximum.Load())
		close(release)
		synctest.Wait()
	})
}

func TestSudoPanicCoverageUnknown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		c := newCollector(collectorOptions{budget: categoryBudget})
		p, ok := runBudget(context.Background(), c, catSudo, func(context.Context) sudoPolicy { panic("LEAKCANARY") })
		b := assembly{accOK: true, acc: accountsData{usable: true, entries: []passwdEntry{{name: "u"}}}, sudoOK: ok, sudo: p}
		r := b.report()
		assert.Equal(t, Coverage{Status: coverageUnknown, Reasons: []string{reasonParseError}}, r.Categories[catSudo])
		assert.Equal(t, []string{reasonParseError}, r.Accounts[0].Sudo.Reasons)
		assert.False(t, r.Accounts[0].Sudo.Complete)
		assert.NotContains(t, logs.String(), "LEAKCANARY")
		assert.Regexp(t, `"source":"pkg/exposure/collect_linux_test.go:[0-9]+"`, logs.String())
	})
}

func TestFailedAccountSourcesWithoutHome(t *testing.T) {
	a := passwdEntry{name: "svc", uid: 1002}
	st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys"), "authorizedprincipalsfile": ptr(".ssh/principals"), "gssapiauthentication": ptr("yes"), "hostbasedauthentication": ptr("yes")}}
	for _, reason := range []string{reasonTimeout, reasonParseError} {
		assert.Empty(t, failedAccountKeys(a, st, reason).files)
		assert.Empty(t, failedAccountCerts(a, st, reason))
		assert.Empty(t, failedAccountTrust(a, st, sshdConfig{}, reason))
	}
}

func TestExternalRecordCapPreservesCorrespondence(t *testing.T) {
	var config strings.Builder
	for i := 0; i < 256; i++ {
		config.WriteString("Match User a\nAuthorizedKeysCommand /bin/true\nAuthorizedPrincipalsCommand /bin/true\nGSSAPIAuthentication yes\n")
	}
	cfg := parseSSHDConfig(mapSource{files: map[string]string{sshdConfigPath: config.String()}})
	b := assembly{sshdOK: true, sshd: sshdData{usable: true, cfg: cfg, daemon: Daemon{Correspondence: "established"}}}
	r := b.report()
	assert.Len(t, r.External, 256)
	assert.Equal(t, "established", r.SSHD.Daemon.Correspondence)
	assert.Equal(t, Coverage{Status: coveragePartial, Reasons: []string{reasonLimitExceeded}}, r.Categories[catSSHD])
}

func TestSystemdRecordDirectoriesAndTypes(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		for _, dir := range []string{"/var/lib/systemd/home", "/etc/userdb", "/run/userdb", "/run/host/userdb", "/usr/local/lib/userdb", "/usr/lib/userdb"} {
			for _, suffix := range []string{".identity", ".user", ".group", ".home"} {
				for _, kind := range []string{"regular", "symlink", "socket", "directory"} {
					t.Run(dir+suffix+"/"+kind, func(t *testing.T) {
						root, owners := attackRoot(t)
						require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0o644))
						require.NoError(t, os.WriteFile(filepath.Join(root, "etc/nsswitch.conf"), []byte("passwd: files systemd\ngroup: files systemd\n"), 0o644))
						require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
						p := filepath.Join(root, dir, "alice"+suffix)
						switch kind {
						case "regular":
							require.NoError(t, os.WriteFile(p, nil, 0o644))
						case "symlink":
							require.NoError(t, os.Symlink("/unread-target", p))
						case "directory":
							require.NoError(t, os.Mkdir(p, 0o755))
						case "socket":
							fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
							require.NoError(t, err)
							defer func() { require.NoError(t, unix.Close(fd)) }()
							parentFD, err := unix.Open(filepath.Dir(p), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
							require.NoError(t, err)
							defer func() { require.NoError(t, unix.Close(parentFD)) }()
							require.NoError(t, unix.Bind(fd, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/alice%s", parentFD, suffix)}))
						}
						d := readAccounts(systemFiles{f: readerFor(t, root, owners)})
						record := kind == "regular" || kind == "symlink"
						homed := dir == "/var/lib/systemd/home"
						assert.Equal(t, record && (homed && suffix == ".identity" || !homed && suffix == ".user"), d.systemdAccounts)
						assert.Equal(t, record && (homed && suffix == ".identity" || !homed && suffix == ".group"), d.systemdGroups)
						assert.Empty(t, d.reasons)
					})
				}
			}
			t.Run(dir+"/unreadable", func(t *testing.T) {
				root, owners := attackRoot(t)
				require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(root, "etc/nsswitch.conf"), []byte("passwd: files systemd\ngroup: files systemd\n"), 0o644))
				require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
				recordOpens(t, []string{dir})
				d := readAccounts(systemFiles{f: readerFor(t, root, owners)})
				assert.True(t, d.systemdAccounts)
				assert.True(t, d.systemdGroups)
				assert.True(t, d.reasons.has(reasonFileUnreadable))
			})
		}
	})
}

func TestFiveHungHomesAcrossCategoriesAndReads(t *testing.T) {
	root, owners := attackRoot(t)
	accounts := make([]passwdEntry, 0, 205)
	for i := range 205 {
		user := fmt.Sprintf("u%03d", i)
		home := "/home/" + user
		require.NoError(t, os.MkdirAll(filepath.Join(root, home, ".ssh"), 0o755))
		owners[home], owners[home+"/.ssh"] = 1001, 1001
		for name, body := range map[string]string{".ssh/authorized_keys": "ssh-ed25519 " + testEd0 + "\n", ".ssh/principals": "alice\n", ".k5login": "alice@EXAMPLE.COM\n"} {
			p := home + "/" + name
			owners[p] = 1001
			require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(body), 0o644))
		}
		accounts = append(accounts, passwdEntry{name: user, uid: 1001, home: home})
	}
	release := make(chan struct{})
	testHookRead = func(p string) {
		for _, a := range accounts[:5] {
			if strings.HasPrefix(p, a.home+"/") {
				<-release
				return
			}
		}
	}
	c := newCollector(collectorOptions{root: root, budget: categoryBudget, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }})
	defer func() { close(release); waitAccountWorkers(c); testHookRead = nil }()
	st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys"), "authorizedprincipalsfile": ptr(".ssh/principals"), "trustedusercakeys": ptr("none"), "gssapiauthentication": ptr("yes")}}
	for range 2 {
		var keys keysData
		var certs certsData
		var trust trustData
		var wg sync.WaitGroup
		wg.Go(func() { keys = c.readKeysBudget(context.Background(), accounts, st, sshdConfig{}) })
		wg.Go(func() { certs = c.readCertsBudget(context.Background(), accounts, st, sshdConfig{}) })
		wg.Go(func() { trust = c.readTrustBudget(context.Background(), accounts, st, sshdConfig{}) })
		wg.Wait()
		for i, a := range accounts {
			files := []Envelope{}
			for _, f := range keys.byUser[a.name].files {
				files = append(files, f.Envelope)
			}
			for _, f := range certs.principals[a.name] {
				files = append(files, f.Envelope)
			}
			for _, f := range trust.files[a.name] {
				files = append(files, f.Envelope)
			}
			require.Len(t, files, 3, a.name)
			for _, f := range files {
				if i < 5 {
					assert.Equal(t, statusTimeout, f.Status, f.Path)
				} else {
					assert.True(t, f.Complete, f.Path)
					assert.Equal(t, statusRead, f.Status, f.Path)
					assert.NotContains(t, f.Reasons, reasonTimeout, f.Path)
				}
			}
		}
		c.accountMu.Lock()
		assert.Equal(t, 15, c.accountCount)
		c.accountMu.Unlock()
	}
}

func TestTwentyHungHomesBoundWorkersAcrossFiveReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newCollector(collectorOptions{budget: categoryBudget})
		release := make(chan struct{})
		defer close(release)
		accounts := []passwdEntry{}
		for i := range 24 {
			accounts = append(accounts, passwdEntry{name: fmt.Sprint(i)})
		}
		baseline := runtime.NumGoroutine()
		for read := range 5 {
			var wg sync.WaitGroup
			for _, cat := range []string{catKeys, catCertificates, catTrust} {
				wg.Go(func() {
					ctx, cancel := context.WithTimeout(context.Background(), categoryBudget)
					defer cancel()
					readAccountResults(ctx, c, cat, accounts, func(a passwdEntry) int {
						if a.name != "0" && a.name != "1" && a.name != "2" && a.name != "3" {
							<-release
						}
						return 1
					}, func(a passwdEntry, value int, reason string) {
						if read == 0 && (a.name == "0" || a.name == "1" || a.name == "2" || a.name == "3") {
							assert.Equal(t, 1, value)
							assert.Empty(t, reason)
						}
					})
				})
			}
			wg.Wait()
			synctest.Wait()
			assert.LessOrEqual(t, runtime.NumGoroutine()-baseline, 28)
			c.accountMu.Lock()
			assert.Equal(t, maxAccountWorkers, c.accountCount)
			assert.LessOrEqual(t, len(c.accountBusy), 28)
			for _, active := range c.accountInFlight {
				assert.LessOrEqual(t, active, 4)
			}
			c.accountMu.Unlock()
		}
	})
}

func TestIncompleteSSHDConfigPropagatesWithoutGuessingTrust(t *testing.T) {
	for _, mode := range []string{"match cap", "unreadable include", "rejected include"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, "hosts", "ubuntu-default")
			spec := loadCase(t, dir)
			root, proc := buildHost(t, dir, spec)
			var config strings.Builder
			reason := reasonFileUnreadable
			if mode == "match cap" {
				for i := range 300 {
					fmt.Fprintf(&config, "Match User u%d\n", i)
					if i == 280 {
						config.WriteString("HostbasedAuthentication yes\nPasswordAuthentication yes\n")
					}
				}
				reason = reasonLimitExceeded
			} else {
				config.WriteString("Include /etc/ssh/hidden\n")
				require.NoError(t, os.WriteFile(filepath.Join(root, "etc/ssh/hidden"), []byte("Match User ubuntu\nHostbasedAuthentication yes\nPasswordAuthentication yes\n"), 0o644))
				if mode == "unreadable include" {
					spec.Unreadable = append(spec.Unreadable, "/etc/ssh/hidden")
				} else {
					if spec.Owners == nil {
						spec.Owners = map[string]uint32{}
					}
					spec.Owners["/etc/ssh/hidden"] = 1001
				}
			}
			require.NoError(t, os.WriteFile(filepath.Join(root, sshdConfigPath), []byte(config.String()), 0o644))
			require.NoError(t, os.Chtimes(filepath.Join(root, sshdConfigPath), fixtureMtime, fixtureMtime))
			opens := recordOpens(t, spec.Unreadable)
			opts := caseOptions(t, dir, spec, root, proc)
			run := opts.runSSHD
			opts.runSSHD = func(ctx context.Context) sshdRun {
				r := run(ctx)
				r.out = append(r.out, "\npasswordauthentication no\nkbdinteractiveauthentication no\nhostbasedauthentication no\nignorerhosts yes\ngssapiauthentication no\nkerberosauthentication no\n"...)
				return r
			}
			r := newCollector(opts).collect(context.Background())
			assert.Equal(t, "unresolved", r.SSHD.Daemon.Correspondence)
			assert.Contains(t, r.Categories[catSSHD].Reasons, reasonSSHDConfigUnresolved)
			for _, cat := range []string{catTrust, catPasswords, catKeys, catCertificates} {
				assert.Equal(t, coveragePartial, r.Categories[cat].Status, cat)
				assert.Contains(t, r.Categories[cat].Reasons, reason, cat)
			}
			assert.Empty(t, r.SystemTrust)
			for _, a := range r.Accounts {
				assert.Empty(t, a.TrustFiles)
			}
			for _, p := range opens() {
				assert.NotContains(t, p, ".k5login")
				assert.NotContains(t, p, ".rhosts")
				assert.NotContains(t, p, ".shosts")
				assert.NotEqual(t, "/etc/hosts.equiv", p)
				assert.NotEqual(t, "/etc/ssh/shosts.equiv", p)
			}
		})
	}
}
