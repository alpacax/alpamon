package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRunCollectCommand_KillsAHungCommandAtTheTimeout(t *testing.T) {
	// Given
	previous := collectCommandTimeout
	t.Cleanup(func() { collectCommandTimeout = previous })
	collectCommandTimeout = 100 * time.Millisecond
	start := time.Now()

	// When
	out, err := runCollectCommand("sh", "-c", "sleep 10 & wait") // the background sleep keeps stdout open after sh is killed

	// Then
	assert.ErrorContains(t, err, "sh timed out after 100ms")
	assert.Nil(t, out)
	assert.Less(t, time.Since(start), 5*time.Second)
}
