package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/go-sqlite"
	"github.com/stretchr/testify/require"
)

func TestSQLiteDSNEnablesForeignKeys(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	var foreignKeys int
	err = conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys)
	require.NoError(t, err)
	require.Equal(t, 1, foreignKeys)

	_, err = conn.ExecContext(ctx, "CREATE TABLE parents (id INTEGER PRIMARY KEY)")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "CREATE TABLE children (parent_id INTEGER REFERENCES parents(id))")
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx, "INSERT INTO children (parent_id) VALUES (1)")
	require.ErrorContains(t, err, "FOREIGN KEY constraint failed")
}
