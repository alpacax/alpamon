//go:build linux

package exposure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const secret = "LEAKCANARY-secret-content"

// attackRoot builds a host root with one account, uid 1001, whose home is
// /home/u, and a root-only file. Ownership is judged through owners: paths
// not listed count as root's.
func attackRoot(t *testing.T) (string, map[string]uint32) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "home/u/.ssh", "srv/elsewhere"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("root:"+secret+":1::::::\n"), 0o640))
	require.NoError(t, os.WriteFile(filepath.Join(root, "srv/elsewhere/authorized_keys"), []byte(secret+"\n"), 0o644))
	owners := map[string]uint32{"/home/u": 1001, "/home/u/.ssh": 1001}
	return root, owners
}

func readerFor(t *testing.T, root string, owners map[string]uint32) *fsReader {
	t.Helper()
	f, err := newFSReader(root, func(p string, uid uint32) uint32 {
		if o, ok := owners[p]; ok {
			return o
		}
		return 0
	})
	require.NoError(t, err)
	t.Cleanup(f.close)
	return f
}

func assertNoContent(t *testing.T, l loaded) {
	t.Helper()
	assert.Nil(t, l.data)
	assert.False(t, l.usable())
	assert.False(t, l.complete())
}

// forBothWalks runs fn with openat2 and with the O_NOFOLLOW fallback.
func forBothWalks(t *testing.T, fn func(t *testing.T)) {
	for _, fallback := range []bool{false, true} {
		name := "openat2"
		if fallback {
			name = "onofollow"
		}
		t.Run(name, func(t *testing.T) {
			testForceNoOpenat2 = fallback
			t.Cleanup(func() { testForceNoOpenat2 = false })
			fn(t)
		})
	}
}

func TestOpenat2IsUsedWhenAvailable(t *testing.T) {
	root, owners := attackRoot(t)
	f := readerFor(t, root, owners)
	l, _ := f.read("/etc/shadow", ownerRule{system: true})
	require.Equal(t, statusRead, l.status)
	if f.noOpenat2.Load() {
		t.Skip("kernel has no openat2; the fallback is covered by the matrix")
	}
}

func TestFileAttackMatrix(t *testing.T) {
	acct := ownerRule{uid: 1001}
	forBothWalks(t, func(t *testing.T) {
		t.Run("symlink to a root-owned file", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.Symlink("/etc/shadow", filepath.Join(root, "home/u/.ssh/authorized_keys")))
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRejected, l.status)
			assert.True(t, l.reasons.has(reasonFileRejected))
			assertNoContent(t, l)
		})
		t.Run("relative symlink inside the account's directory", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh/keys"), []byte("x\n"), 0o600))
			owners["/home/u/.ssh/keys"] = 1001
			require.NoError(t, os.Symlink("keys", filepath.Join(root, "home/u/.ssh/authorized_keys")))
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("intermediate directory symlink", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.RemoveAll(filepath.Join(root, "home/u/.ssh")))
			require.NoError(t, os.Symlink("/srv/elsewhere", filepath.Join(root, "home/u/.ssh")))
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("hard link", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.Link(filepath.Join(root, "etc/shadow"), filepath.Join(root, "home/u/.ssh/authorized_keys")))
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("FIFO does not block", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, unix.Mkfifo(filepath.Join(root, "home/u/.ssh/authorized_keys"), 0o600))
			done := make(chan loaded, 1)
			go func() {
				l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
				done <- l
			}()
			select {
			case l := <-done:
				assert.Equal(t, statusRejected, l.status)
				assertNoContent(t, l)
			case <-time.After(5 * time.Second):
				t.Fatal("reading a FIFO blocked")
			}
		})
		t.Run("device file", func(t *testing.T) {
			root, owners := attackRoot(t)
			p := filepath.Join(root, "home/u/.ssh/authorized_keys")
			err := unix.Mknod(p, unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3)))
			if err != nil {
				t.Logf("mknod needs privilege (%v); proving the type check with an injected fstat result", err)
				require.NoError(t, os.WriteFile(p, []byte(secret), 0o600))
				owners["/home/u/.ssh/authorized_keys"] = 1001
				testHookFstat = func(path string, st *unix.Stat_t) {
					if path == "/home/u/.ssh/authorized_keys" {
						st.Mode = st.Mode&^unix.S_IFMT | unix.S_IFCHR
					}
				}
				t.Cleanup(func() { testHookFstat = nil })
			}
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("foreign owner", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh/authorized_keys"), []byte(secret), 0o600))
			owners["/home/u/.ssh/authorized_keys"] = 2000
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("system file not owned by root", func(t *testing.T) {
			root, owners := attackRoot(t)
			owners["/etc/shadow"] = 1001
			l, _ := readerFor(t, root, owners).read("/etc/shadow", ownerRule{system: true})
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("system file under a directory not owned by root", func(t *testing.T) {
			root, owners := attackRoot(t)
			owners["/etc"] = 1001
			l, _ := readerFor(t, root, owners).read("/etc/shadow", ownerRule{system: true})
			assert.Equal(t, statusRejected, l.status)
			assertNoContent(t, l)
		})
		t.Run("1 MiB plus one byte", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh/authorized_keys"), bytes.Repeat([]byte("a"), maxReadBytes+1), 0o600))
			owners["/home/u/.ssh/authorized_keys"] = 1001
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRead, l.status)
			assert.True(t, l.reasons.has(reasonLimitExceeded))
			assertNoContent(t, l)
		})
		t.Run("exactly 1 MiB is read", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh/authorized_keys"), bytes.Repeat([]byte("a"), maxReadBytes), 0o600))
			owners["/home/u/.ssh/authorized_keys"] = 1001
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.True(t, l.usable())
			assert.Len(t, l.data, maxReadBytes)
		})
		t.Run("size change during the read", func(t *testing.T) {
			root, owners := attackRoot(t)
			p := filepath.Join(root, "home/u/.ssh/authorized_keys")
			require.NoError(t, os.WriteFile(p, []byte("ssh-ed25519 AAAA\n"), 0o600))
			owners["/home/u/.ssh/authorized_keys"] = 1001
			testHookAfterRead = func(path string) {
				f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
				require.NoError(t, err)
				_, _ = f.WriteString(secret + "\n")
				_ = f.Close()
			}
			t.Cleanup(func() { testHookAfterRead = nil })
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", acct)
			assert.Equal(t, statusRead, l.status)
			assert.True(t, l.reasons.has(reasonConcurrentChange))
			assertNoContent(t, l)
		})
		t.Run("absent under a pinned parent", func(t *testing.T) {
			root, owners := attackRoot(t)
			l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys2", acct)
			assert.Equal(t, statusAbsent, l.status)
			assert.True(t, l.complete())
		})
		t.Run("dot-dot never resolves", func(t *testing.T) {
			root, owners := attackRoot(t)
			l, _ := readerFor(t, root, owners).read("/home/u/../../etc/shadow", acct)
			assert.Equal(t, statusUnresolved, l.status)
			assertNoContent(t, l)
		})
	})
}

func TestSystemSymlinkWalk(t *testing.T) {
	forBothWalks(t, func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			target string
		}{
			{"relative", "usr/bin"},
			{"absolute", "/usr/bin"},
			{"dot components", "usr/../usr/./bin"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				root, owners := attackRoot(t)
				require.NoError(t, os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755))
				require.NoError(t, os.Symlink(tc.target, filepath.Join(root, "bin")))
				f := readerFor(t, root, owners)
				_, l := f.statDir("/bin", ownerRule{uid: 2})
				assert.Equal(t, statusRead, l.status)
				_, l = f.statDir("/bin/.ssh", ownerRule{uid: 2})
				assert.Equal(t, statusAbsent, l.status)
				d := readKeys(f, []passwdEntry{{name: "bin", uid: 2, home: "/bin"}},
					&sshdT{effective: map[string]*string{"authorizedkeysfile": ptr(".ssh/authorized_keys")}}, sshdConfig{})
				assert.NotContains(t, d.reasons.list(), reasonHomeUnreadable)
				require.Len(t, d.byUser["bin"].files, 1)
				assert.Equal(t, statusAbsent, d.byUser["bin"].files[0].Status)
			})
		}
		for _, tc := range []struct {
			name   string
			parent string
			owner  string
			mode   os.FileMode
		}{
			{"account-owned symlink", "srv", "/srv/link", 0o755},
			{"account-owned parent", "home/u", "", 0o755},
			{"sticky writable parent", "srv", "", os.ModeSticky | 0o777},
			{"group-writable parent", "srv", "", 0o775},
		} {
			t.Run(tc.name, func(t *testing.T) {
				root, owners := attackRoot(t)
				if tc.owner != "" {
					owners[tc.owner] = 1001
				}
				require.NoError(t, os.Chmod(filepath.Join(root, tc.parent), tc.mode))
				require.NoError(t, os.Symlink("/srv/elsewhere", filepath.Join(root, tc.parent, "link")))
				l, _ := readerFor(t, root, owners).read("/"+tc.parent+"/link/authorized_keys", ownerRule{uid: 1001})
				assert.Equal(t, statusRejected, l.status)
				assert.True(t, l.reasons.has(reasonFileRejected))
				assertNoContent(t, l)
			})
		}
		for _, hops := range []int{40, 41} {
			t.Run(fmt.Sprintf("%d hops", hops), func(t *testing.T) {
				root, owners := attackRoot(t)
				for i := range hops {
					target := fmt.Sprintf("link%d", i+1)
					if i == hops-1 {
						target = "elsewhere"
					}
					require.NoError(t, os.Symlink(target, filepath.Join(root, "srv", fmt.Sprintf("link%d", i))))
				}
				l, _ := readerFor(t, root, owners).read("/srv/link0/authorized_keys", ownerRule{uid: 1001})
				if hops == 40 {
					assert.True(t, l.usable())
				} else {
					assert.Equal(t, statusRejected, l.status)
					assert.True(t, l.reasons.has(reasonFileRejected))
					assertNoContent(t, l)
				}
			})
		}
		t.Run("target enters account control", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.Symlink("/home/u/link", filepath.Join(root, "srv/link")))
			require.NoError(t, os.Symlink("/srv/elsewhere", filepath.Join(root, "home/u/link")))
			owners["/home/u/link"] = 1001
			l, _ := readerFor(t, root, owners).read("/srv/link/authorized_keys", ownerRule{uid: 1001})
			assert.Equal(t, statusRejected, l.status)
			assert.True(t, l.reasons.has(reasonFileRejected))
			assertNoContent(t, l)
		})
		t.Run("dot-dot does not restore symlink trust", func(t *testing.T) {
			root, owners := attackRoot(t)
			require.NoError(t, os.Symlink("/home/u/../../srv/second", filepath.Join(root, "srv/link")))
			require.NoError(t, os.Symlink("elsewhere", filepath.Join(root, "srv/second")))
			l, _ := readerFor(t, root, owners).read("/srv/link/authorized_keys", ownerRule{uid: 1001})
			assert.Equal(t, statusRejected, l.status)
			assert.True(t, l.reasons.has(reasonFileRejected))
			assertNoContent(t, l)
		})
	})
}

// A read blocked on a hung mount is abandoned as a timeout; while that worker
// is outstanding the next read records the category as a timeout without
// starting a second worker, and the other categories still report.
func TestHungReadIsAbandonedAndCounted(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0o644))
	release := make(chan struct{})
	var blocked atomic.Int32
	testHookRead = func(p string) {
		if p == "/etc/shadow" {
			blocked.Add(1)
			<-release
		}
	}
	t.Cleanup(func() { testHookRead = nil })
	opts := collectorOptions{
		root: root, procRoot: filepath.Join(root, "proc"), hostname: func() string { return "h" },
		runSSHD:  func(context.Context) sshdRun { return sshdRun{notInstalled: true} },
		mapOwner: func(p string, uid uint32) uint32 { return owners[p] },
		budget:   100 * time.Millisecond,
	}
	c := newCollector(opts)

	r := c.collect(context.Background())
	assert.Equal(t, Coverage{Status: coverageUnknown, Reasons: []string{reasonTimeout}}, r.Categories[catPasswords])
	assert.Equal(t, coverageCovered, r.Categories[catAccounts].Status, "one failed category never blocks the others")
	require.Len(t, r.Accounts, 1)
	assert.Equal(t, shadowUnreadable, r.Accounts[0].Shadow.Status)

	r = c.collect(context.Background())
	assert.Equal(t, []string{reasonTimeout}, r.Categories[catPasswords].Reasons)
	assert.Equal(t, int32(1), blocked.Load(), "no second worker starts behind the abandoned one")

	close(release)
	require.Eventually(t, func() bool { return !c.busy[catPasswords].Load() }, 5*time.Second, 10*time.Millisecond)
	r = c.collect(context.Background())
	assert.NotContains(t, r.Categories[catPasswords].Reasons, reasonTimeout)
	assert.Equal(t, int32(2), blocked.Load())
}

// The walk never hands back a descriptor for a path component that is not a
// directory.
func TestRegularFileAsDirectoryIsRejected(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.RemoveAll(filepath.Join(root, "home/u/.ssh")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "home/u/.ssh"), []byte(secret), 0o600))
	l, _ := readerFor(t, root, owners).read("/home/u/.ssh/authorized_keys", ownerRule{uid: 1001})
	assert.Equal(t, statusRejected, l.status)
	assertNoContent(t, l)
}

func TestStatusOfErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status string
	}{
		{unix.ENOENT, statusAbsent},
		{unix.ELOOP, statusRejected},
		{unix.EXDEV, statusRejected},
		{unix.ENOTDIR, statusRejected},
		{unix.EACCES, statusUnreadable},
		{unix.EIO, statusUnreadable},
		{errors.New("other"), statusUnreadable},
	} {
		got, _ := statusOf(tc.err)
		assert.Equal(t, tc.status, got, tc.err.Error())
	}
}
