package testutil

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/stretchr/testify/require"
)

// ErrCommitFailed is what every Commit on a CommitFailingClient returns.
var ErrCommitFailed = errors.New("testutil: injected commit failure")

// CommitFailingClient opens path with transactions that roll back and return ErrCommitFailed on Commit.
// Open path with db.InitTestDB first: it registers the sqlite3 driver and migrates the schema.
func CommitFailingClient(t *testing.T, path string) *ent.Client {
	t.Helper()
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	drv, err := entsql.Open(dialect.SQLite, fmt.Sprintf("file:%s?cache=shared&_pragma=foreign_keys(1)", abs))
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(commitFailingDriver{drv}))
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type commitFailingDriver struct{ dialect.Driver }

func (d commitFailingDriver) Tx(ctx context.Context) (dialect.Tx, error) {
	tx, err := d.Driver.Tx(ctx)
	if err != nil {
		return nil, err
	}
	return commitFailingTx{tx}, nil
}

type commitFailingTx struct{ dialect.Tx }

func (tx commitFailingTx) Commit() error {
	_ = tx.Tx.Rollback()
	return ErrCommitFailed
}
