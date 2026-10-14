package testutil

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/stretchr/testify/require"
)

// ErrCommitFailed is what every Commit on a CommitFailingClient returns.
var ErrCommitFailed = errors.New("testutil: injected commit failure")

// CommitFailingClient migrates the database at path and opens it with transactions that roll back
// and return ErrCommitFailed on Commit.
func CommitFailingClient(t *testing.T, path string) *ent.Client {
	t.Helper()
	require.NoError(t, db.InitTestDB(path).Close()) // InitTestDB also registers the sqlite3 driver.
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	drv, err := entsql.Open(dialect.SQLite, db.SQLiteDSN(abs))
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
