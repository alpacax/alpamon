//go:build linux

package exposure

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTriggerHoldsOnePendingRead(t *testing.T) {
	for len(triggers) > 0 {
		<-triggers
	}
	for range 5 {
		Trigger()
	}
	assert.Len(t, triggers, 1)
	<-triggers
}

func TestExpandPath(t *testing.T) {
	for _, tc := range []struct {
		tmpl, want string
		ok         bool
	}{
		{".ssh/authorized_keys", "/home/u/.ssh/authorized_keys", true},
		{"%h/.ssh/keys", "/home/u/.ssh/keys", true},
		{"/etc/ssh/keys/%u", "/etc/ssh/keys/u", true},
		{"/etc/ssh/keys/%%u", "/etc/ssh/keys/%u", true},
		{"/etc/ssh/keys/%U", "", false},
		{"/etc/ssh/keys/%", "", false},
		{"%h/../x", "", false},
	} {
		got, ok := expandPath(tc.tmpl, "/home/u", "u")
		assert.Equal(t, tc.ok, ok, tc.tmpl)
		if tc.ok {
			assert.Equal(t, tc.want, got, tc.tmpl)
		}
	}
	got, ok := expandPath(".ssh/authorized_keys", "/", "root")
	assert.True(t, ok)
	assert.Equal(t, "/.ssh/authorized_keys", got)
}

func TestMasterArgsFromListenerTitle(t *testing.T) {
	assert.Equal(t, sshdArgs{}, masterArgs([]string{"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}))
	assert.Equal(t, sshdArgs{configPath: "/etc/ssh/alt"}, masterArgs([]string{"sshd: /usr/sbin/sshd -D -f /etc/ssh/alt [listener] 0 of 10-100 startups"}))
	assert.Equal(t, sshdArgs{hasOverride: true}, masterArgs([]string{"sshd: /usr/sbin/sshd -o UsePAM=no [listener] 0 of 10-100 startups"}))
	assert.Equal(t, sshdArgs{hasOverride: true}, masterArgs([]string{"something else entirely"}))
	assert.Equal(t, sshdArgs{}, masterArgs([]string{"/usr/sbin/sshd", "-D"}))
}

// correspondenceFor builds a proc tree with the given sshd masters and
// returns the daemon record for a configuration last changed at mtime.
func correspondenceFor(t *testing.T, masters [][]string, mtime time.Time, socket bool) daemon {
	t.Helper()
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	require.NoError(t, os.MkdirAll(proc, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "stat"), []byte("btime 1700000000\n"), 0o644))
	for i, argv := range masters {
		pd := filepath.Join(proc, strconv.Itoa(100+i))
		require.NoError(t, os.MkdirAll(pd, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(pd, "stat"), []byte(strconv.Itoa(100+i)+" (sshd) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100000 1 1\n"), 0o644))
		cmd := ""
		for _, a := range argv {
			cmd += a + "\x00"
		}
		require.NoError(t, os.WriteFile(filepath.Join(pd, "status"), []byte("Uid:\t0\t0\t0\t0\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(pd, "cmdline"), []byte(cmd), 0o644))
	}
	if socket {
		dir := filepath.Join(root, "etc/systemd/system/sockets.target.wants")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.Symlink("/usr/lib/systemd/system/ssh.socket", filepath.Join(dir, "ssh.socket")))
	}
	c := newCollector(collectorOptions{procRoot: proc})
	f, err := newFSReader(root, rootOwned)
	require.NoError(t, err)
	defer f.close()
	cfg := sshdConfig{readAll: true, files: []inspectedFile{{path: sshdConfigPath, mtime: mtime}}}
	return c.correspondence(f, cfg)
}

func TestCorrespondence(t *testing.T) {
	old := time.Unix(1600000000, 0)
	newer := time.Unix(1800000000, 0) // after the master started at btime+1000s
	yes, no := true, false
	plain := []string{"/usr/sbin/sshd", "-D"}
	assert.Equal(t, daemon{ConfigPathMatches: &yes, Correspondence: "established"}, correspondenceFor(t, [][]string{plain}, old, false))
	assert.Equal(t, daemon{ConfigPathMatches: &yes, Correspondence: "unresolved"}, correspondenceFor(t, [][]string{plain}, newer, false), "config changed after the master started")
	assert.Equal(t, daemon{ConfigPathMatches: &yes, Correspondence: "unresolved"}, correspondenceFor(t, [][]string{{"/usr/sbin/sshd", "-o", "UsePAM=no"}}, old, false))
	assert.Equal(t, daemon{ConfigPathMatches: &no, Correspondence: "unresolved"}, correspondenceFor(t, [][]string{{"/usr/sbin/sshd", "-f", "/etc/ssh/alt"}}, old, false))
	assert.Equal(t, daemon{Correspondence: "unresolved"}, correspondenceFor(t, [][]string{plain, plain}, old, false), "two listeners")
	assert.Equal(t, daemon{Correspondence: "unresolved"}, correspondenceFor(t, nil, old, false))
	assert.Equal(t, daemon{Correspondence: "established"}, correspondenceFor(t, nil, newer, true), "socket activation reads the configuration per connection")
}
