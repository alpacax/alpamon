package accessoutboxtest

import (
	"context"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/accessoutbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RunContract checks that each Store from open behaves as accessoutbox.Store
// documents. open must return an empty Store for each call.
func RunContract(t *testing.T, open func(t *testing.T) accessoutbox.Store) {
	at := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

	t.Run("InsertRefusesPastTheBoundAndSkipsHeldIDs", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		stored, refused, err := store.Insert(ctx, []accessoutbox.Row{row("a", at)}, 2)
		require.NoError(t, err)
		require.Equal(t, 1, stored)
		require.Zero(t, refused)

		stored, refused, err = store.Insert(ctx, []accessoutbox.Row{row("a", at), row("b", at), row("c", at)}, 2)

		require.NoError(t, err)
		assert.Equal(t, 1, stored, "a is already held and b reaches the bound")
		assert.Equal(t, 1, refused, "c is past the bound")
		assert.Equal(t, []string{"a", "b"}, ids(t, store, at))
	})

	t.Run("InsertStoresARepeatedIDInOneBatchOnce", func(t *testing.T) {
		store := open(t)

		stored, refused, err := store.Insert(context.Background(), []accessoutbox.Row{row("a", at), row("a", at)}, 10)

		require.NoError(t, err)
		assert.Equal(t, 1, stored, "the second copy is skipped like an already held row")
		assert.Zero(t, refused)
		assert.Equal(t, []string{"a"}, ids(t, store, at))
	})

	t.Run("InsertKeepsTheRowAsGivenWithZeroAttempts", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		want := accessoutbox.Row{
			ID:            "a",
			Payload:       []byte(`{"event_id":"a"}`),
			CreatedAt:     at,
			Attempts:      7,
			NextAttemptAt: at.Add(time.Second),
		}

		_, _, err := store.Insert(ctx, []accessoutbox.Row{want}, 10)

		require.NoError(t, err)
		due, err := store.Due(ctx, at.Add(time.Second), at.Add(time.Hour), 10)
		require.NoError(t, err)
		require.Len(t, due, 1)
		assert.Equal(t, want.Payload, due[0].Payload)
		assert.True(t, want.CreatedAt.Equal(due[0].CreatedAt), "created at %s", due[0].CreatedAt)
		assert.True(t, want.NextAttemptAt.Equal(due[0].NextAttemptAt), "next attempt at %s", due[0].NextAttemptAt)
		assert.Zero(t, due[0].Attempts, "a new row has made no attempt")
	})

	t.Run("AnyReportsHeldRows", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		held, err := store.Any(ctx)
		require.NoError(t, err)
		require.False(t, held)

		insert(t, store, row("a", at))

		held, err = store.Any(ctx)
		require.NoError(t, err)
		assert.True(t, held)
	})

	t.Run("DueOrdersByCreationThenIDAndHonorsTheLimit", func(t *testing.T) {
		store := open(t)
		insert(t, store, row("c", at), row("b", at), row("a", at.Add(-time.Second)))

		due, err := store.Due(context.Background(), at, at.Add(time.Hour), 2)

		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, rowIDs(due))
	})

	t.Run("DueSkipsRowsBetweenNowAndSkewed", func(t *testing.T) {
		store := open(t)
		now, skewed := at, at.Add(time.Hour)
		insert(t, store,
			withNext(row("now", at), now),
			withNext(row("later", at.Add(time.Second)), now.Add(time.Minute)),
			withNext(row("atSkew", at.Add(2*time.Second)), skewed),
			withNext(row("pastSkew", at.Add(3*time.Second)), skewed.Add(time.Second)),
		)

		due, err := store.Due(context.Background(), now, skewed, 10)

		require.NoError(t, err)
		assert.Equal(t, []string{"now", "pastSkew"}, rowIDs(due),
			"due at or before now, or past skewed, which only a clock set back explains")
	})

	t.Run("EarliestAttemptIsTheSoonestNextAttempt", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		_, held, err := store.EarliestAttempt(ctx)
		require.NoError(t, err)
		require.False(t, held, "an empty store holds nothing")
		insert(t, store, withNext(row("a", at), at.Add(time.Minute)), withNext(row("b", at), at.Add(time.Second)))

		earliest, held, err := store.EarliestAttempt(ctx)

		require.NoError(t, err)
		require.True(t, held)
		assert.True(t, at.Add(time.Second).Equal(earliest), "earliest %s", earliest)
	})

	t.Run("RescheduleSetsAttemptsAndNextAttempt", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		insert(t, store, row("a", at))

		require.NoError(t, store.Reschedule(ctx, "a", 3, at.Add(time.Minute)))

		due, err := store.Due(ctx, at.Add(time.Minute), at.Add(time.Hour), 10)
		require.NoError(t, err)
		require.Len(t, due, 1)
		assert.Equal(t, 3, due[0].Attempts)
		assert.True(t, at.Add(time.Minute).Equal(due[0].NextAttemptAt))
	})

	t.Run("RemoveDeletesTheRow", func(t *testing.T) {
		store := open(t)
		insert(t, store, row("a", at), row("b", at))

		require.NoError(t, store.Remove(context.Background(), "a"))

		assert.Equal(t, []string{"b"}, ids(t, store, at))
	})

	t.Run("MissingRowsAreNotErrors", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()

		assert.NoError(t, store.Reschedule(ctx, "gone", 1, at))
		assert.NoError(t, store.Remove(ctx, "gone"))
	})

	t.Run("ReleaseAfterPullsLaterAttemptsBack", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		insert(t, store, withNext(row("early", at), at.Add(time.Second)), withNext(row("late", at), at.Add(time.Hour)))

		require.NoError(t, store.ReleaseAfter(ctx, at.Add(time.Minute)))

		due, err := store.Due(ctx, at.Add(time.Minute), at.Add(2*time.Hour), 10)
		require.NoError(t, err)
		require.Len(t, due, 2, "both rows are due once the late one is pulled back")
		next := map[string]time.Time{}
		for _, r := range due {
			next[r.ID] = r.NextAttemptAt
		}
		assert.True(t, at.Add(time.Second).Equal(next["early"]), "an earlier attempt stays put")
		assert.True(t, at.Add(time.Minute).Equal(next["late"]), "a later attempt moves to at")
	})

	t.Run("CreatedBeforeIsStrict", func(t *testing.T) {
		store := open(t)
		ctx := context.Background()
		insert(t, store, row("old", at.Add(-time.Second)), row("cutoff", at), row("new", at.Add(time.Second)))

		count, err := store.CountCreatedBefore(ctx, at)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		removed, err := store.RemoveCreatedBefore(ctx, at)

		require.NoError(t, err)
		assert.Equal(t, 1, removed)
		assert.Equal(t, []string{"cutoff", "new"}, ids(t, store, at.Add(time.Second)))
	})
}

func row(id string, createdAt time.Time) accessoutbox.Row {
	return accessoutbox.Row{ID: id, Payload: []byte(`{}`), CreatedAt: createdAt, NextAttemptAt: createdAt}
}

func withNext(r accessoutbox.Row, next time.Time) accessoutbox.Row {
	r.NextAttemptAt = next
	return r
}

func insert(t *testing.T, store accessoutbox.Store, rows ...accessoutbox.Row) {
	t.Helper()
	stored, _, err := store.Insert(context.Background(), rows, len(rows)+100)
	require.NoError(t, err)
	require.Equal(t, len(rows), stored)
}

// ids lists the rows due at now, which with no backoff applied is every row.
func ids(t *testing.T, store accessoutbox.Store, now time.Time) []string {
	t.Helper()
	due, err := store.Due(context.Background(), now, now.Add(24*time.Hour), 100)
	require.NoError(t, err)
	return rowIDs(due)
}

func rowIDs(rows []accessoutbox.Row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}
