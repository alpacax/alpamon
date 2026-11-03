package accessoutbox

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBusy_RecognizesOnlyALockedDatabase(t *testing.T) {
	assert.True(t, IsBusy(errors.New("database is locked (5) (SQLITE_BUSY)")))
	assert.True(t, IsBusy(errors.New("database table is locked: access_event_outbox")))
	assert.True(t, IsBusy(errors.New("sqlite: step: SQLITE_BUSY")))
	assert.False(t, IsBusy(errors.New("disk I/O error")))
	assert.False(t, IsBusy(errors.New("UNIQUE constraint failed: access_event_outbox.id")))
}
