package executor

import (
	"runtime"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

func TestPlatformHandlers(t *testing.T) {
	// platformHandlers requires non-nil deps to construct handlers,
	// but we only need to verify the count and names. Use zero-value deps
	// which is safe because we don't call Execute on the handlers.
	deps := platformHandlerDeps{}
	handlers := platformHandlers(deps)

	// Collect handler names for assertion messages
	var names []string
	for _, h := range handlers {
		names = append(names, h.Name())
	}

	switch runtime.GOOS {
	case "linux":
		// Linux: system, group, user, firewall, tunnel
		assertHandlerCount(t, handlers, 5, names)
		assertHasHandler(t, handlers, string(common.System))
		assertHasHandler(t, handlers, string(common.Group))
		assertHasHandler(t, handlers, string(common.User))
		assertHasHandler(t, handlers, string(common.Firewall))
		assertHasHandler(t, handlers, string(common.Tunnel))
	case "darwin":
		// macOS: system, tunnel (no user, group, firewall)
		assertHandlerCount(t, handlers, 2, names)
		assertHasHandler(t, handlers, string(common.System))
		assertHasHandler(t, handlers, string(common.Tunnel))
		assertNoHandler(t, handlers, string(common.User))
		assertNoHandler(t, handlers, string(common.Group))
		assertNoHandler(t, handlers, string(common.Firewall))
	default:
		t.Skipf("no handler expectations defined for %s", runtime.GOOS)
	}
}

func assertHandlerCount(t *testing.T, handlers []common.Handler, expected int, names []string) {
	t.Helper()
	if len(handlers) != expected {
		t.Errorf("platformHandlers() returned %d handlers %v, want %d", len(handlers), names, expected)
	}
}

func assertHasHandler(t *testing.T, handlers []common.Handler, name string) {
	t.Helper()
	for _, h := range handlers {
		if h.Name() == name {
			return
		}
	}
	t.Errorf("platformHandlers() missing handler %q", name)
}

func assertNoHandler(t *testing.T, handlers []common.Handler, name string) {
	t.Helper()
	for _, h := range handlers {
		if h.Name() == name {
			t.Errorf("platformHandlers() should not include handler %q on %s", name, runtime.GOOS)
			return
		}
	}
}
