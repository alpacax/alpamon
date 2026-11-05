package runner

import (
	"context"

	"github.com/alpacax/alpamon/v2/internal/safego"
)

// goPumps starts each loop of one session under its name. A loop that panics
// cancels the session, so the others wind down instead of waiting on it.
func goPumps(cancel context.CancelFunc, pumps map[string]func()) {
	for name, pump := range pumps {
		safego.Go(name, pump, cancel)
	}
}
