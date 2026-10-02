package executor

import (
	"runtime"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
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
		assertHasHandler(t, names, string(common.System))
		assertHasHandler(t, names, string(common.Group))
		assertHasHandler(t, names, string(common.User))
		assertHasHandler(t, names, string(common.Firewall))
		assertHasHandler(t, names, string(common.Tunnel))
	case "darwin":
		// macOS: system, tunnel (no user, group, firewall)
		assertHandlerCount(t, handlers, 2, names)
		assertHasHandler(t, names, string(common.System))
		assertHasHandler(t, names, string(common.Tunnel))
		assertNoHandler(t, names, string(common.User))
		assertNoHandler(t, names, string(common.Group))
		assertNoHandler(t, names, string(common.Firewall))
	case "windows":
		// Windows: system, tunnel (no user, group, firewall)
		assertHandlerCount(t, handlers, 2, names)
		assertHasHandler(t, names, string(common.System))
		assertHasHandler(t, names, string(common.Tunnel))
		assertNoHandler(t, names, string(common.User))
		assertNoHandler(t, names, string(common.Group))
		assertNoHandler(t, names, string(common.Firewall))
	default:
		t.Skipf("no handler expectations defined for %s", runtime.GOOS)
	}
}

func assertHandlerCount(t *testing.T, handlers []common.Handler, expected int, names []string) {
	t.Helper()
	assert.Len(t, handlers, expected, "platformHandlers() returned handlers %v", names)
}

func assertHasHandler(t *testing.T, names []string, name string) {
	t.Helper()
	assert.Contains(t, names, name, "platformHandlers() missing handler")
}

func assertNoHandler(t *testing.T, names []string, name string) {
	t.Helper()
	assert.NotContains(t, names, name, "platformHandlers() should not include handler on %s", runtime.GOOS)
}
