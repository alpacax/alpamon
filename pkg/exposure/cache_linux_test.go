//go:build linux

package exposure

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type sourceOpens struct {
	mu     sync.Mutex
	counts map[string]int
	denied string
}

func countSourceOpens(t *testing.T) *sourceOpens {
	t.Helper()
	o := &sourceOpens{counts: map[string]int{}}
	testHookOpen = func(p string) error {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.counts[p]++
		if p == o.denied {
			return unix.EACCES
		}
		return nil
	}
	t.Cleanup(func() { testHookOpen = nil })
	return o
}

func (o *sourceOpens) take(paths ...string) []int {
	o.mu.Lock()
	defer o.mu.Unlock()
	counts := make([]int, len(paths))
	for i, p := range paths {
		counts[i] = o.counts[p]
		delete(o.counts, p)
	}
	return counts
}

func cacheReader(t *testing.T, root string, owners map[string]uint32) *fsReader {
	t.Helper()
	fs := readerFor(t, root, owners)
	fs.cache = newSourceCache()
	now := time.Now().Add(10 * time.Second)
	fs.now = func() time.Time { return now }
	return fs
}

func TestShadowCacheReadsOnlyChanges(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		for _, change := range []string{"size", "mtime", "inode", "permissions", "ctime", "owner"} {
			t.Run(change, func(t *testing.T) {
				root, owners := attackRoot(t)
				p := filepath.Join(root, "etc/shadow")
				require.NoError(t, os.WriteFile(p, []byte("u:!:1::::::\n"), 0o640))
				fs := cacheReader(t, root, owners)
				ctime := unix.NsecToTimespec(fs.now().Add(-10 * time.Second).UnixNano())
				if change == "ctime" {
					fs.cacheStat = func(p string, st *unix.Stat_t) {
						if p == "/etc/shadow" {
							st.Ctim = ctime
						}
					}
				}
				opens := countSourceOpens(t)
				first := readShadow(systemFiles{f: fs})
				assert.True(t, first.usable)
				assert.Empty(t, first.reasons)
				assert.Equal(t, passwordNone, first.infos["u"].state)
				assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
				assert.Equal(t, first, readShadow(systemFiles{f: fs}))
				assert.Equal(t, []int{0}, opens.take("/etc/shadow"))
				before, err := os.Stat(p)
				require.NoError(t, err)
				var beforeStat unix.Stat_t
				require.NoError(t, unix.Stat(p, &beforeStat))
				originalID := fs.cacheIdentity("/etc/shadow", beforeStat)
				switch change {
				case "size":
					require.NoError(t, os.WriteFile(p, []byte("u::123::::::\n"), 0o640))
				case "mtime":
					require.NoError(t, os.Chtimes(p, before.ModTime(), before.ModTime().Add(time.Second)))
				case "inode":
					replacement := filepath.Join(root, "replacement")
					require.NoError(t, os.WriteFile(replacement, []byte("u:*:1::::::\n"), 0o640))
					require.NoError(t, os.Chtimes(replacement, before.ModTime(), before.ModTime()))
					require.NoError(t, os.Rename(replacement, p))
				case "permissions":
					require.NoError(t, os.Chmod(p, 0o600))
				case "ctime":
					// Set the cache's ctime explicitly, independent of kernel ticks.
					ctime = unix.NsecToTimespec(fs.now().Add(-9 * time.Second).UnixNano())
				case "owner":
					owners["/etc/shadow"] = 2000
				}
				var afterStat unix.Stat_t
				require.NoError(t, unix.Stat(p, &afterStat))
				if change == "inode" {
					assert.NotEqual(t, beforeStat.Ino, afterStat.Ino)
					assert.Equal(t, beforeStat.Size, afterStat.Size)
					assert.Equal(t, beforeStat.Mtim, afterStat.Mtim)
				}
				if change == "ctime" {
					assert.Equal(t, beforeStat.Mode, afterStat.Mode)
					assert.Equal(t, beforeStat.Mtim, afterStat.Mtim)
					afterID := fs.cacheIdentity("/etc/shadow", afterStat)
					assert.NotEqual(t, originalID.ctime, afterID.ctime)
					afterID.ctime = originalID.ctime
					assert.Equal(t, originalID, afterID)
				}
				var reads int
				testHookRead = func(string) { reads++ }
				t.Cleanup(func() { testHookRead = nil })
				got := readShadow(systemFiles{f: fs})
				if change == "owner" {
					assert.False(t, got.usable)
					assert.Equal(t, []string{reasonFileRejected}, got.reasons.list())
					assert.Equal(t, 0, reads)
					assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
				} else {
					assert.True(t, got.usable)
					assert.Equal(t, 1, reads)
					assert.Empty(t, got.reasons)
					assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
					if change == "size" {
						assert.Equal(t, passwordEmpty, got.infos["u"].state)
					} else {
						assert.Equal(t, passwordNone, got.infos["u"].state)
					}
				}
			})
		}
	})
}

func TestSourceCacheRetriesFailedAndPartialReads(t *testing.T) {
	for _, failure := range []string{"unreadable", "parse", "concurrent"} {
		t.Run(failure, func(t *testing.T) {
			root, owners := attackRoot(t)
			p := filepath.Join(root, "etc/shadow")
			require.NoError(t, os.WriteFile(p, []byte("u:!:1::::::\n"), 0o640))
			fs := cacheReader(t, root, owners)
			opens := countSourceOpens(t)
			switch failure {
			case "unreadable":
				opens.denied = "/etc/shadow"
			case "parse":
				require.NoError(t, os.WriteFile(p, []byte("invalid\n"), 0o640))
			case "concurrent":
				testHookAfterRead = func(string) { require.NoError(t, os.Truncate(p, 0)) }
				t.Cleanup(func() { testHookAfterRead = nil })
			}
			first := readShadow(systemFiles{f: fs})
			want := map[string]string{"unreadable": reasonFileUnreadable, "parse": reasonParseError, "concurrent": reasonConcurrentChange}[failure]
			assert.Equal(t, []string{want}, first.reasons.list())
			assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
			if failure == "parse" {
				again := readShadow(systemFiles{f: fs})
				assert.Equal(t, []string{reasonParseError}, again.reasons.list())
				assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
			}
			opens.denied = ""
			testHookAfterRead = nil
			if failure != "unreadable" {
				require.NoError(t, os.WriteFile(p, []byte("u:!:1::::::\n"), 0o640))
			}
			second := readShadow(systemFiles{f: fs})
			assert.True(t, second.usable)
			assert.Empty(t, second.reasons)
			assert.Equal(t, passwordNone, second.infos["u"].state)
			assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
		})
	}
}

func TestDirectorySourceCacheTracksEntrySet(t *testing.T) {
	for _, change := range []string{"added", "removed", "renamed"} {
		t.Run(change, func(t *testing.T) {
			root, owners := attackRoot(t)
			dir := filepath.Join(root, "etc/sudoers.d")
			require.NoError(t, os.Mkdir(dir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(root, "etc/sudoers"), []byte("@includedir /etc/sudoers.d\n"), 0o640))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "first"), []byte("u ALL=(ALL) ALL\n"), 0o640))
			fs := cacheReader(t, root, owners)
			opens := countSourceOpens(t)
			read := func() accountSudo {
				policy := readCachedSudo(systemFiles{f: fs}, "host")
				return policy.forAccount("u", func(string) bool { return false })
			}
			first := read()
			assert.True(t, first.Complete)
			require.Len(t, first.Grants, 1)
			assert.Equal(t, "/etc/sudoers.d/first", first.Grants[0].Source)
			assert.Equal(t, []int{1, 1}, opens.take("/etc/sudoers", "/etc/sudoers.d/first"))
			assert.Equal(t, first, read())
			assert.Equal(t, []int{0, 0}, opens.take("/etc/sudoers", "/etc/sudoers.d/first"))
			switch change {
			case "added":
				require.NoError(t, os.WriteFile(filepath.Join(dir, "second"), []byte("u ALL=(ALL) ALL\n"), 0o640))
			case "removed":
				require.NoError(t, os.Remove(filepath.Join(dir, "first")))
			case "renamed":
				require.NoError(t, os.Rename(filepath.Join(dir, "first"), filepath.Join(dir, "second")))
			}
			got := read()
			assert.True(t, got.Complete)
			assert.Equal(t, []int{1}, opens.take("/etc/sudoers"))
			switch change {
			case "added":
				assert.Len(t, got.Grants, 2)
				assert.Equal(t, []int{1, 1}, opens.take("/etc/sudoers.d/first", "/etc/sudoers.d/second"))
			case "removed":
				assert.Empty(t, got.Grants)
				assert.Equal(t, []int{0}, opens.take("/etc/sudoers.d/first"))
			case "renamed":
				require.Len(t, got.Grants, 1)
				assert.Equal(t, "/etc/sudoers.d/second", got.Grants[0].Source)
				assert.Equal(t, []int{0, 1}, opens.take("/etc/sudoers.d/first", "/etc/sudoers.d/second"))
			}
		})
	}
}

func TestCollectionCacheStartAndDailyFullRead(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts/ubuntu-default")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	opts := caseOptions(t, dir, spec, root, proc)
	for p, data := range map[string]string{
		"/etc/ssh/ca":                  "ssh-ed25519 " + testEd0 + "\n",
		"/home/ubuntu/.ssh/principals": "operator\n",
		"/home/ubuntu/.k5login":        "ubuntu@EXAMPLE.COM\n",
		"/home/ubuntu/.rhosts":         "example.com ubuntu\n",
		"/home/ubuntu/.shosts":         "example.com ubuntu\n",
		"/etc/hosts.equiv":             "example.com ubuntu\n",
		"/etc/ssh/shosts.equiv":        "example.com ubuntu\n",
		"/etc/krb5.conf":               "[libdefaults]\ndefault_realm = EXAMPLE.COM\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(data), 0o644))
	}
	now := time.Now().Add(10 * time.Second)
	opts.now = func() time.Time { return now }
	var runs int
	run := opts.runSSHD
	opts.runSSHD = func(ctx context.Context) sshdRun {
		runs++
		result := run(ctx)
		result.out = append(result.out, "\nauthorizedprincipalsfile .ssh/principals\ntrustedusercakeys /etc/ssh/ca\ngssapiauthentication yes\nignorerhosts no\n"...)
		return result
	}
	c := newCollector(opts)
	opens := countSourceOpens(t)
	paths := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/90-cloud-init-users", "/home/ubuntu/.ssh/authorized_keys", "/var/log/wtmp", "/var/log/lastlog", "/etc/ssh/sshd_config",
		"/etc/ssh/ca", "/home/ubuntu/.ssh/principals", "/home/ubuntu/.k5login", "/home/ubuntu/.rhosts", "/home/ubuntu/.shosts", "/etc/hosts.equiv", "/etc/ssh/shosts.equiv", "/etc/krb5.conf",
		"/etc/group", "/etc/shells", "/etc/nsswitch.conf", "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf", "/etc/sudoers.d/README"}
	first := c.collect(context.Background())
	assert.Equal(t, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, opens.take(paths...))
	now = now.Add(23*time.Hour + 59*time.Minute)
	second := c.collect(context.Background())
	assert.Equal(t, first, second)
	assert.Equal(t, []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, opens.take(paths...))
	now = now.Add(time.Minute + time.Nanosecond)
	third := c.collect(context.Background())
	assert.Equal(t, first, third)
	assert.Equal(t, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, opens.take(paths...))
	assert.Equal(t, first, c.collect(context.Background()))
	assert.Equal(t, []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, opens.take(paths...))
	assert.Equal(t, 4, runs)
	// A fresh collector cannot inherit this process's earlier successful reads.
	assert.Equal(t, first, newCollector(opts).collect(context.Background()))
	assert.Equal(t, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, opens.take(paths...))
}

func TestCategoryWithoutSuccessfulReadIsNotCovered(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0o644))
	opens := countSourceOpens(t)
	opens.denied = "/etc/shadow"
	c := newCollector(collectorOptions{root: root, procRoot: root, hostname: func() string { return "host" }, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }, budget: categoryBudget, runSSHD: func(context.Context) sshdRun { return sshdRun{notInstalled: true} }})
	for range 2 {
		r := c.collect(context.Background())
		assert.Equal(t, coverage{Status: coverageUnknown, Reasons: []string{reasonFileUnreadable}}, r.Categories[catPasswords])
		assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
	}
}

func TestAccountSourceCachePreservesFactsAndChecksDirectories(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		root, owners := attackRoot(t)
		p := "/home/u/.ssh/authorized_keys"
		owners[p] = 1001
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("ssh-ed25519 "+testEd0+" label\n"), 0o600))
		fs := cacheReader(t, root, owners)
		opens := countSourceOpens(t)
		read := func() keyFile {
			budget := maxKeysPerAccount
			kf, _, _ := readKeyFile(fs, p, ownerRule{uid: 1001}, &budget)
			return kf
		}
		first := read()
		require.True(t, first.Complete)
		require.Len(t, first.Keys, 1)
		assert.Equal(t, []int{1}, opens.take(p))
		// Report capping must not edit the stored source envelope or its facts.
		first.Keys = nil
		first.Complete = false
		cached := read()
		assert.True(t, cached.Complete)
		assert.Len(t, cached.Keys, 1)
		assert.Equal(t, []int{0}, opens.take(p))
		for _, action := range []string{"added", "renamed", "removed"} {
			switch action {
			case "added":
				require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh/extra"), nil, 0o600))
			case "renamed":
				require.NoError(t, os.Rename(filepath.Join(root, "home/u/.ssh/extra"), filepath.Join(root, "home/u/.ssh/renamed")))
			case "removed":
				require.NoError(t, os.Remove(filepath.Join(root, "home/u/.ssh/renamed")))
			}
			assert.Equal(t, cached, read())
			assert.Equal(t, []int{1}, opens.take(p), action)
		}
		// The cached file cannot hide a newly rejected account parent chain.
		owners[p] = 0
		got := read()
		assert.Equal(t, statusRejected, got.Status)
		assert.Equal(t, []string{reasonFileRejected}, got.Reasons)
		assert.Empty(t, got.Keys)
		assert.Equal(t, []int{1}, opens.take(p))
	})
}

func TestPrincipalsAndTrustCachePerPath(t *testing.T) {
	root, owners := attackRoot(t)
	for p, data := range map[string]string{
		"/etc/ssh/ca":             "ssh-ed25519 " + testEd0 + "\n",
		"/home/u/.ssh/principals": "operator\n",
		"/home/u/.k5login":        "u@EXAMPLE.COM\n",
		"/home/u/.rhosts":         "example.com u\n",
		"/etc/hosts.equiv":        "example.com u\n",
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(data), 0o644))
	}
	fs := cacheReader(t, root, owners)
	opens := countSourceOpens(t)
	read := func() []any {
		return []any{
			readCAFile(fs, "/etc/ssh/ca"),
			readPrincipalsSource(fs, "/home/u/.ssh/principals", ownerRule{uid: 1001}),
			readTrustSource(fs, "/home/u/.k5login", ownerRule{uid: 1001}, "k5login"),
			readTrustSource(fs, "/home/u/.rhosts", ownerRule{uid: 1001}, "rhosts"),
			readSystemTrustSource(fs, "/etc/hosts.equiv"),
		}
	}
	paths := []string{"/etc/ssh/ca", "/home/u/.ssh/principals", "/home/u/.k5login", "/home/u/.rhosts", "/etc/hosts.equiv"}
	first := read()
	assert.Equal(t, []int{1, 1, 1, 1, 1}, opens.take(paths...))
	assert.Equal(t, first, read())
	assert.Equal(t, []int{0, 0, 0, 0, 0}, opens.take(paths...))
	require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh/principals"), []byte("admin\n"), 0o644))
	got := read()
	assert.Equal(t, []principalEntry{{Principals: []string{"admin"}, Options: []string{}}}, got[1].(principalsFile).Entries)
	assert.Equal(t, []int{0, 1, 0, 0, 0}, opens.take(paths...))
}

func TestLastlogCacheIncludesRequestedOffsets(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/log"), 0o755))
	raw := encodeLastlog(t, []caseLogin{{UID: 1, Line: "pts/1", Time: "2026-11-01T00:00:00Z"}, {UID: 2, Line: "pts/2", Time: "2026-11-02T00:00:00Z"}})
	require.NoError(t, os.WriteFile(filepath.Join(root, lastlogPath), raw, 0o644))
	fs := cacheReader(t, root, owners)
	opens := countSourceOpens(t)
	one := readLastlogSource(fs, []int64{lastlogSize})
	assert.True(t, one.usable)
	require.Len(t, one.records, 1)
	assert.Equal(t, []int{1}, opens.take(lastlogPath))
	assert.Equal(t, one, readLastlogSource(fs, []int64{lastlogSize}))
	assert.Equal(t, []int{0}, opens.take(lastlogPath))
	two := readLastlogSource(fs, []int64{lastlogSize, 2 * lastlogSize})
	assert.True(t, two.usable)
	require.Len(t, two.records, 2)
	assert.Equal(t, ptr("pts/2"), two.records[2*lastlogSize].tty)
	assert.Equal(t, []int{1}, opens.take(lastlogPath))
}

func TestSourceCacheRejectsRecentTimestamps(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		for _, source := range []string{"file", "directory"} {
			for _, timestamp := range []string{"mtime", "ctime"} {
				t.Run(source+" "+timestamp, func(t *testing.T) {
					root, owners := attackRoot(t)
					p := "/home/u/.ssh/principals"
					require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("first\n"), 0o644))
					fs := cacheReader(t, root, owners)
					now := time.Unix(2000000000, int64(250*time.Millisecond))
					fs.now = func() time.Time { return now }
					old := unix.Timespec{Sec: 1999999990}
					recent := unix.Timespec{Sec: 2000000000}
					target := p
					if source == "directory" {
						target = "/home/u/.ssh"
					}
					fs.cacheStat = func(name string, st *unix.Stat_t) {
						st.Mtim, st.Ctim = old, old
						if name == target {
							if timestamp == "mtime" {
								st.Mtim = recent
							} else {
								st.Ctim = recent
							}
						}
					}
					opens := countSourceOpens(t)
					read := func() principalsFile { return readPrincipalsSource(fs, p, ownerRule{uid: 1001}) }
					first := read()
					assert.True(t, first.Complete)
					assert.Equal(t, []principalEntry{{Principals: []string{"first"}, Options: []string{}}}, first.Entries)
					assert.Equal(t, []int{1}, opens.take(p))
					assert.Empty(t, fs.cache.entries)
					// Model a same-size rewrite in the same coarse timestamp tick.
					require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("other\n"), 0o644))
					now = now.Add(250 * time.Millisecond)
					second := read()
					assert.True(t, second.Complete)
					assert.Equal(t, []principalEntry{{Principals: []string{"other"}, Options: []string{}}}, second.Entries)
					assert.Equal(t, []int{1}, opens.take(p))
					assert.Empty(t, fs.cache.entries)
					// Crossing the window needs one real read before reuse is allowed.
					now = time.Unix(2000000002, 0)
					assert.Equal(t, second, read())
					assert.Equal(t, []int{1}, opens.take(p))
					assert.Empty(t, fs.cache.entries, "the two-second boundary is still too recent")
					now = now.Add(time.Nanosecond)
					assert.Equal(t, second, read())
					assert.Equal(t, []int{1}, opens.take(p))
					require.Len(t, fs.cache.entries, 1)
					assert.Equal(t, second, read())
					assert.Equal(t, []int{0}, opens.take(p))
				})
			}
		}
	})
}

func TestSourceCacheRejectsRecentRecordedStat(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("u:!:1::::::\n"), 0o640))
	fs := cacheReader(t, root, owners)
	opens := countSourceOpens(t)
	first := readShadow(systemFiles{f: fs})
	assert.True(t, first.usable)
	assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
	entry := fs.cache.entries["shadow:/etc/shadow"]
	require.NotEmpty(t, entry.dependencies)
	for i := range entry.dependencies {
		dep := &entry.dependencies[i]
		if !dep.absent {
			dep.statTime = time.Unix(dep.id.ctime.Sec, dep.id.ctime.Nsec).Add(time.Second)
		}
	}
	fs.cache.entries["shadow:/etc/shadow"] = entry
	assert.Equal(t, first, readShadow(systemFiles{f: fs}))
	assert.Equal(t, []int{1}, opens.take("/etc/shadow"))
}

func TestKerberosReasonsMatchWithoutCache(t *testing.T) {
	for _, failure := range []string{"limit", "concurrent"} {
		t.Run(failure, func(t *testing.T) {
			var outcomes [][]string
			for _, cached := range []bool{false, true} {
				root, owners := attackRoot(t)
				p := filepath.Join(root, "etc/krb5.conf")
				require.NoError(t, os.WriteFile(p, []byte("[libdefaults]\n"), 0o644))
				if failure == "limit" {
					require.NoError(t, os.Truncate(p, maxReadBytes+1))
				}
				if failure == "concurrent" {
					testHookAfterRead = func(name string) {
						if name == "/etc/krb5.conf" {
							require.NoError(t, os.Truncate(p, 0))
						}
					}
					t.Cleanup(func() { testHookAfterRead = nil })
				}
				fs := readerFor(t, root, owners)
				if cached {
					fs = cacheReader(t, root, owners)
				}
				st := &sshdT{effective: map[string]*string{"gssapiauthentication": ptr("yes")}}
				d := readTrust(fs, systemFiles{f: fs}, nil, st, sshdConfig{}, false)
				outcomes = append(outcomes, d.reasons.list())
				testHookAfterRead = nil
			}
			if failure == "limit" {
				assert.Equal(t, []string{reasonKerberosMappingUnresolved, reasonLimitExceeded}, outcomes[0])
			} else {
				assert.Equal(t, []string{reasonConcurrentChange, reasonKerberosMappingUnresolved}, outcomes[0])
			}
			assert.Equal(t, outcomes[0], outcomes[1])
		})
	}
}

func TestCollectionPrunesRemovedAccounts(t *testing.T) {
	dir := filepath.Join(fixturesDir, "hosts/ubuntu-default")
	spec := loadCase(t, dir)
	root, proc := buildHost(t, dir, spec)
	opts := caseOptions(t, dir, spec, root, proc)
	now := time.Now().Add(10 * time.Second)
	opts.now = func() time.Time { return now }
	c := newCollector(opts)
	first := c.collect(context.Background())
	assert.NotEmpty(t, first.Accounts)
	key := "keys:1000:/home/ubuntu/.ssh/authorized_keys"
	c.cache.mu.Lock()
	_, found := c.cache.entries[key]
	c.cache.mu.Unlock()
	require.True(t, found)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0::/root:/bin/bash\n"), 0o644))
	second := c.collect(context.Background())
	require.Len(t, second.Accounts, 1)
	assert.Equal(t, "root", second.Accounts[0].Username)
	c.cache.mu.Lock()
	assert.NotContains(t, c.cache.entries, key)
	c.cache.mu.Unlock()
}

func TestCollectionPrunesOldEpochAndLateWorkers(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("u:!:1::::::\n"), 0o640))
	fs := cacheReader(t, root, owners)
	fs.collection = fs.cache.beginCollection()
	readShadow(systemFiles{f: fs})
	require.Contains(t, fs.cache.entries, "shadow:/etc/shadow")
	// An old entry touched by the new collection is still discarded.
	collection := fs.cache.beginCollection()
	entry := fs.cache.entries["shadow:/etc/shadow"]
	entry.touched = collection
	fs.cache.entries["shadow:/etc/shadow"] = entry
	fs.cache.finishCollection(collection, 1)
	assert.Empty(t, fs.cache.entries)
	readShadow(systemFiles{f: fs})
	assert.Empty(t, fs.cache.entries, "an abandoned worker cannot refill a pruned cache")
}

func TestSharedHomeKeyCacheIncludesAccountUID(t *testing.T) {
	root, owners := attackRoot(t)
	p := "/home/u/.ssh/authorized_keys"
	require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte("ssh-ed25519 "+testEd0+"\n"), 0o644))
	fs := cacheReader(t, root, owners)
	opens := countSourceOpens(t)
	accounts := []passwdEntry{{name: "first", uid: 1001, home: "/home/u"}, {name: "second", uid: 1002, home: "/home/u"}}
	st := &sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys")}}
	fs.collection = fs.cache.beginCollection()
	first := readKeys(fs, accounts, st, sshdConfig{})
	fs.cache.finishCollection(fs.collection, fs.epoch)
	require.Len(t, first.byUser["first"].files, 1)
	require.Len(t, first.byUser["second"].files, 1)
	assert.True(t, first.byUser["first"].files[0].Complete)
	assert.True(t, first.byUser["second"].files[0].Complete)
	assert.Len(t, first.byUser["first"].files[0].Keys, 1)
	assert.Len(t, first.byUser["second"].files[0].Keys, 1)
	assert.Equal(t, []int{2}, opens.take(p))
	fs.collection = fs.cache.beginCollection()
	assert.Equal(t, first, readKeys(fs, accounts, st, sshdConfig{}))
	fs.cache.finishCollection(fs.collection, fs.epoch)
	assert.Equal(t, []int{0}, opens.take(p))
	assert.Contains(t, fs.cache.entries, "keys:1001:"+p)
	assert.Contains(t, fs.cache.entries, "keys:1002:"+p)
}

func TestSharedHomeParsedSourcesIncludeAccountUID(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		root, owners := attackRoot(t)
		for p, data := range map[string]string{
			"/home/u/.ssh/principals": "operator\n",
			"/home/u/.k5login":        "shared@EXAMPLE.COM\n",
			"/home/u/.rhosts":         "example.com shared\n",
			"/home/u/.shosts":         "example.com shared\n",
			"/etc/ssh/ca":             "ssh-ed25519 " + testEd0 + "\n",
		} {
			require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(data), 0o644))
		}
		fs := cacheReader(t, root, owners)
		opens := countSourceOpens(t)
		accounts := []passwdEntry{{name: "first", uid: 1001, home: "/home/u"}, {name: "second", uid: 1002, home: "/home/u"}}
		st := &sshdT{effective: map[string]*string{
			"authorizedprincipalsfile": ptr(".ssh/principals"),
			"trustedusercakeys":        ptr("/etc/ssh/ca"),
			"gssapiauthentication":     ptr("yes"),
			"ignorerhosts":             ptr("no"),
		}}
		paths := []string{"/home/u/.ssh/principals", "/home/u/.k5login", "/home/u/.rhosts", "/home/u/.shosts", "/etc/ssh/ca"}
		fs.collection = fs.cache.beginCollection()
		certs := readCerts(fs, systemFiles{f: fs}, accounts, st, sshdConfig{}, false)
		trust := readTrust(fs, systemFiles{f: fs}, accounts, st, sshdConfig{}, false)
		fs.cache.finishCollection(fs.collection, fs.epoch)
		assert.Empty(t, certs.reasons)
		assert.Empty(t, trust.reasons)
		for _, user := range []string{"first", "second"} {
			require.Len(t, certs.principals[user], 1)
			assert.True(t, certs.principals[user][0].Complete)
			assert.Equal(t, []principalEntry{{Principals: []string{"operator"}, Options: []string{}}}, certs.principals[user][0].Entries)
			require.Len(t, trust.files[user], 3)
			for _, file := range trust.files[user] {
				assert.Equal(t, statusRead, file.Status)
				assert.True(t, file.Complete)
				assert.Len(t, file.Entries, 1)
			}
		}
		require.NotNil(t, certs.userCA)
		assert.True(t, certs.userCA.Complete)
		assert.Len(t, certs.userCA.CAs, 1)
		assert.Equal(t, []int{2, 2, 2, 2, 1}, opens.take(paths...))

		fs.collection = fs.cache.beginCollection()
		assert.Equal(t, certs, readCerts(fs, systemFiles{f: fs}, accounts, st, sshdConfig{}, false))
		assert.Equal(t, trust, readTrust(fs, systemFiles{f: fs}, accounts, st, sshdConfig{}, false))
		fs.cache.finishCollection(fs.collection, fs.epoch)
		assert.Equal(t, []int{0, 0, 0, 0, 0}, opens.take(paths...))
		for _, uid := range []string{"1001", "1002"} {
			assert.Contains(t, fs.cache.entries, "principals:"+uid+":/home/u/.ssh/principals")
			assert.Contains(t, fs.cache.entries, "trust-k5login:"+uid+":/home/u/.k5login")
			assert.Contains(t, fs.cache.entries, "trust-rhosts:"+uid+":/home/u/.rhosts")
			assert.Contains(t, fs.cache.entries, "trust-shosts:"+uid+":/home/u/.shosts")
		}
		assert.Contains(t, fs.cache.entries, "ca:/etc/ssh/ca")
	})
}
