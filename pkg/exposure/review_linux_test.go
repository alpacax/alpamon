//go:build linux

package exposure

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestObservedAtClockStep(t *testing.T) {
	logs := captureLogs(t)
	s := testService(nil, func(context.Context) *Report { return sampleReport() })
	now := s.now()
	s.lastObserved = now.Add(24 * time.Hour)
	var sleeps []time.Duration
	s.sleep = func(_ context.Context, d time.Duration) bool { sleeps = append(sleeps, d); return true }
	r, _ := s.buildReport(context.Background())
	require.NotNil(t, r)
	assert.Empty(t, sleeps)
	assert.Equal(t, now.Format(time.RFC3339), r.ObservedAt)
	assert.Equal(t, now, s.lastObserved)
	assert.Equal(t, 1, strings.Count(logs.String(), `"level":"warn"`))
	s.buildReport(context.Background())
	assert.Equal(t, []time.Duration{time.Second}, sleeps)
	assert.Equal(t, now.Add(time.Second), s.lastObserved)
	assert.Equal(t, 1, strings.Count(logs.String(), `"level":"warn"`))
}
func procMasterFixture(t *testing.T, uid string, cmdline bool) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "100"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1700000000\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "100/stat"), []byte("100 (sshd) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100000 1 1\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "100/status"), []byte("Uid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n"), 0644))
	if cmdline {
		require.NoError(t, os.WriteFile(filepath.Join(root, "100/cmdline"), []byte("/usr/sbin/sshd\x00-D\x00"), 0644))
	}
	return root
}
func TestSSHDMasterRequiresRoot(t *testing.T) {
	got, ok := findSSHDMasters(procMasterFixture(t, "1000", true))
	assert.True(t, ok)
	assert.Empty(t, got)
}
func TestSSHDVanishingMaster(t *testing.T) {
	got, ok := findSSHDMasters(procMasterFixture(t, "0", false))
	assert.True(t, ok)
	assert.Empty(t, got)
}
func TestReadValidatedInode(t *testing.T) {
	root, owners := attackRoot(t)
	p := "/home/u/.ssh/authorized_keys"
	owners[p] = 1001
	target := filepath.Join(root, p)
	require.NoError(t, os.WriteFile(target, []byte("original"), 0600))
	fs := readerFor(t, root, owners)
	testHookFstat = func(path string, _ *unix.Stat_t) {
		if path == p {
			require.NoError(t, os.Rename(target, target+".old"))
			require.NoError(t, os.WriteFile(target, []byte("replacement"), 0600))
		}
	}
	defer func() { testHookFstat = nil }()
	got, _ := fs.read(p, ownerRule{uid: 1001})
	assert.True(t, got.complete())
	assert.Equal(t, "original", string(got.data))
}
func TestPhaseTwoDoesNotWaitForSudo(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/sudoers"), []byte("u ALL=ALL\n"), 0644))
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		blocked := make(chan struct{})
		phaseTwo := make(chan struct{}, 1)
		testHookRead = func(p string) {
			if p == sudoersPath {
				close(blocked)
				<-release
			}
		}
		defer func() { testHookRead = nil }()
		installReadHook(t, func(stage string) {
			if stage == "starter:"+catKeys {
				phaseTwo <- struct{}{}
			}
		})
		c := newCollector(collectorOptions{root: root, procRoot: root, hostname: func() string { return "host" }, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }, budget: categoryBudget, runSSHD: func(context.Context) sshdRun { return sshdRun{notInstalled: true} }})
		done := make(chan struct{})
		go func() { c.collect(context.Background()); close(done) }()
		<-blocked
		synctest.Wait()
		assert.Len(t, phaseTwo, 1, "keys must start while the sudo read is blocked")
		close(release)
		<-done
	})
}
