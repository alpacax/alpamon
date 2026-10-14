package cpu

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dbFileName = "cleanup.db"

func TestDeleteQueriesReturnCommitError(t *testing.T) {
	setupClient := db.InitTestDB(dbFileName)
	t.Cleanup(func() {
		_ = setupClient.Close()
		require.NoError(t, os.Remove(dbFileName))
	})
	client := testutil.CommitFailingClient(t, dbFileName)

	for _, table := range tables {
		t.Run(string(table), func(t *testing.T) {
			query, exist := deleteQueryMap[table]
			require.True(t, exist)

			err := query(context.Background(), client, time.Now())

			assert.ErrorIs(t, err, testutil.ErrCommitFailed)
		})
	}
}
