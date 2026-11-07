package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/alpacax/alpamon/v2/pkg/exposure"
)

func TestTakeExposureKey(t *testing.T) {
	rest, only := takeExposureKey([]string{"groups", "exposure", "users"})
	if exposure.Supported {
		assert.Equal(t, []string{"groups", "users"}, rest)
	} else {
		assert.Equal(t, []string{"groups", "exposure", "users"}, rest, "ignored as an unknown key, as before")
	}
	assert.False(t, only)

	rest, only = takeExposureKey([]string{"exposure"})
	assert.Equal(t, exposure.Supported, only, "a sync of only exposure never becomes a full sync")
	if exposure.Supported {
		assert.Empty(t, rest)
	}

	rest, only = takeExposureKey(nil)
	assert.Nil(t, rest)
	assert.False(t, only)
}
