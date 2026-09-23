package runner

import (
	"context"
	"testing"
)

// NewChunkCallback lets runner_test, which imports pkg/executor and so cannot
// live in package runner, drive the real callback.
func NewChunkCallback(cr *CommandRunner) func(ctx context.Context, content string) {
	return cr.newChunkCallback()
}

// StartFakeAlpacon exposes startFakeAlpacon; contents preserves delivery order.
func StartFakeAlpacon(t *testing.T) (cleanup func(), contents func() []string) {
	t.Helper()
	_, cleanup, mu, bodies := startFakeAlpacon(t)
	contents = func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(*bodies))
		for i, c := range *bodies {
			out[i] = c.content
		}
		return out
	}
	return cleanup, contents
}
