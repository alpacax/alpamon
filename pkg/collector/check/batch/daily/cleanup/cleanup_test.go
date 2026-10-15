package cpu

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteQueriesReturnCommitError(t *testing.T) {
	client := dbtest.CommitFailingClient(t, filepath.Join(t.TempDir(), "cleanup.db"))

	for _, table := range tables {
		t.Run(string(table), func(t *testing.T) {
			query, exist := deleteQueryMap[table]
			require.True(t, exist)

			err := query(context.Background(), client, time.Now())

			assert.ErrorIs(t, err, dbtest.ErrCommitFailed)
		})
	}
}
