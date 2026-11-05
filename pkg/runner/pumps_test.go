package runner

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
)

func TestGoPumpsCancelsTheSessionWhicheverPumpPanics(t *testing.T) {
	names := []string{"first", "second", "third"}
	for _, panicking := range names {
		t.Run(panicking, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				ctx, cancel := context.WithCancel(t.Context())
				pumps := make(map[string]func(), len(names))
				for _, name := range names {
					pumps[name] = func() { <-ctx.Done() }
				}
				pumps[panicking] = func() { panic("pump panicked") }

				goPumps(cancel, pumps)

				<-ctx.Done() // a pump that panicked without cancelling would deadlock the bubble here
				assert.Contains(t, logs.String(), `"goroutine":"`+panicking+`"`)
			})
		})
	}
}
