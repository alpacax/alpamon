//go:build linux

package exposure

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestCollectionSharesRootAndRetainsAbandonedReader(t *testing.T) {
	root, owners := attackRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1001:1001::/home/u:/bin/sh\n"), 0644))
	var opens atomic.Int32
	installReadHook(t, func(stage string) {
		if stage == "open-root" {
			opens.Add(1)
		}
	})
	c := newCollector(collectorOptions{root: root, procRoot: root, hostname: func() string { return "host" }, mapOwner: func(p string, _ uint32) uint32 { return owners[p] }, budget: categoryBudget, runSSHD: func(context.Context) sshdRun { return sshdRun{notInstalled: true} }})
	c.collect(context.Background())
	assert.EqualValues(t, 1, opens.Load())
	fs, err := newFSReader(root, rootOwned)
	require.NoError(t, err)
	shared := &collectionFS{reader: fs}
	shared.refs.Store(1)
	ctx := context.WithValue(context.Background(), collectionFSKey{}, shared)
	release := retainCollectionFS(ctx)
	shared.release()
	var st unix.Stat_t
	require.NoError(t, unix.Fstat(fs.rootFD, &st), "an outstanding worker pins the root")
	release()
	assert.ErrorIs(t, unix.Fstat(fs.rootFD, &st), unix.EBADF)
}
