package accessoutboxtest

import (
	"context"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/accessoutbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemStore_MeetsTheStoreContract(t *testing.T) {
	RunContract(t, func(*testing.T) accessoutbox.Store { return NewMemStore() })
}

func TestMemStore_FailOnFailsTheNamedOpWithoutChangingRows(t *testing.T) {
	store := NewMemStore()
	at := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	store.Seed(row("a", at))
	store.FailOn(func(op Op) error {
		if op == OpRemove {
			return ErrLocked
		}
		return nil
	})

	err := store.Remove(context.Background(), "a")

	require.ErrorIs(t, err, ErrLocked)
	assert.True(t, accessoutbox.IsBusy(err), "ErrLocked reads as a locked database")
	assert.Equal(t, []string{"a"}, rowIDs(store.Rows()))
}
