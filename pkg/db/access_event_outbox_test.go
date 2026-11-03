package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/accessoutbox"
	"github.com/alpacax/alpamon/v2/pkg/accessoutbox/accessoutboxtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestOutboxStore(t *testing.T, path string) *AccessEventOutboxStore {
	t.Helper()
	client := InitTestDB(path)
	t.Cleanup(func() { _ = client.Close() })
	return NewAccessEventOutboxStore(client)
}

func outboxRow(id string, createdAt time.Time) accessoutbox.Row {
	return accessoutbox.Row{ID: id, Payload: []byte(`{}`), CreatedAt: createdAt, NextAttemptAt: createdAt}
}

func TestAccessEventOutboxStore_MeetsTheStoreContract(t *testing.T) {
	accessoutboxtest.RunContract(t, func(t *testing.T) accessoutbox.Store {
		return newTestOutboxStore(t, filepath.Join(t.TempDir(), "outbox.db"))
	})
}

func TestAccessEventOutboxStore_RowsOutliveTheClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	at := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	first := InitTestDB(path)
	t.Cleanup(func() { _ = first.Close() }) // a failed require below must not leave the file open on Windows
	_, _, err := NewAccessEventOutboxStore(first).Insert(context.Background(), []accessoutbox.Row{outboxRow("a", at)}, 10)
	require.NoError(t, err)
	require.NoError(t, first.Close())

	reopened := newTestOutboxStore(t, path)

	due, err := reopened.Due(context.Background(), at, at.Add(time.Hour), 10)
	require.NoError(t, err)
	require.Len(t, due, 1, "a restarted agent finds the held row")
	assert.Equal(t, "a", due[0].ID)
}

// The outbox retries only what accessoutbox.IsBusy recognizes, so this pins
// that the driver's error for a held write lock is one of them.
func TestAccessEventOutboxStore_LockedDatabaseReadsAsBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	store := newTestOutboxStore(t, path)
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	conn, err := raw.Conn(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE")
	require.NoError(t, err)

	_, _, err = store.Insert(context.Background(), []accessoutbox.Row{outboxRow("a", time.Now().UTC())}, 10)

	require.Error(t, err)
	assert.True(t, accessoutbox.IsBusy(err), "a held write lock must read as busy: %v", err)
	_, err = conn.ExecContext(context.Background(), "COMMIT")
	assert.NoError(t, err)
}
