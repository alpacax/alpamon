// Package dbtest holds a commit-failing ent client for tests. It is apart from testutil so tests that
// only need testutil do not link ent and SQLite, and pkg/db tests can import testutil.
package dbtest

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/alpacax/alpamon/v2/internal/sqlitedsn"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/stretchr/testify/require"
)

// ErrCommitFailed is what every Commit on a CommitFailingClient returns.
var ErrCommitFailed = errors.New("dbtest: injected commit failure")

// CommitFailingClient migrates the database at path and opens it with transactions that roll back
// and return ErrCommitFailed on Commit.
func CommitFailingClient(t *testing.T, path string) *ent.Client {
	t.Helper()
	require.NoError(t, db.InitTestDB(path).Close()) // InitTestDB also registers the sqlite3 driver.
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	drv, err := entsql.Open(dialect.SQLite, sqlitedsn.For(abs))
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
	_ = tx.Rollback()
	return ErrCommitFailed
}
