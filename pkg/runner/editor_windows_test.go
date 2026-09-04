//go:build windows

package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUserDataDirIsUnsupportedOnWindows turns the header comment in
// editor_windows.go into behavior: enabling editor tunnels on Windows without
// a junction-safe implementation goes red here rather than quietly writing
// through whatever the path resolves to.
func TestUserDataDirIsUnsupportedOnWindows(t *testing.T) {
	assert.ErrorIs(t, setupUserDataFiles(t.Context(), t.TempDir(), "d", nil, nil), errUserDataDirUnsupported)
	assert.ErrorIs(t, chownTreeNoFollow(t.Context(), t.TempDir(), 0, 0), errUserDataDirUnsupported)

	_, err := setupUserDataDir(t.Context(), t.TempDir(), "", "")
	assert.ErrorIs(t, err, errUserDataDirUnsupported)
}
