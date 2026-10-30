package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/accessoutbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestOutboxStore(t *testing.T) *AccessEventOutboxStore {
	t.Helper()
	client := InitTestDB(filepath.Join(t.TempDir(), "outbox.db"))
	t.Cleanup(func() { _ = client.Close() })
	return NewAccessEventOutboxStore(client)
}

func outboxRow(id string, createdAt time.Time) accessoutbox.Row {
	return accessoutbox.Row{
		ID:            id,
		Payload:       []byte(`{}`),
		CreatedAt:     createdAt,
		NextAttemptAt: createdAt,
	}
}

func TestAccessEventOutboxStore_InsertRefusesPastTheBoundAndSkipsHeldIDs(t *testing.T) {
	store := newTestOutboxStore(t)
	ctx := context.Background()
	at := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	stored, refused, err := store.Insert(ctx, []accessoutbox.Row{outboxRow("a", at)}, 2)
	require.NoError(t, err)
	require.Equal(t, 1, stored)
	require.Zero(t, refused)

	rows := []accessoutbox.Row{outboxRow("a", at), outboxRow("b", at), outboxRow("c", at)}
	stored, refused, err = store.Insert(ctx, rows, 2)

	require.NoError(t, err)
	assert.Equal(t, 1, stored, "a is already held and b reaches the bound")
	assert.Equal(t, 1, refused, "c is past the bound")
	due, err := store.Due(ctx, at, at.Add(time.Hour), 10)
	require.NoError(t, err)
	ids := make([]string, 0, len(due))
	for _, row := range due {
		ids = append(ids, row.ID)
	}
	assert.Equal(t, []string{"a", "b"}, ids)
}

func TestAccessEventOutboxStore_MissingRowsAreNotErrors(t *testing.T) {
	store := newTestOutboxStore(t)
	ctx := context.Background()

	_, held, err := store.EarliestAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, held, "an empty table holds nothing")
	assert.NoError(t, store.Reschedule(ctx, "gone", 1, time.Now().UTC()))
	assert.NoError(t, store.Remove(ctx, "gone"))
}
