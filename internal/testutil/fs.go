// Package testutil provides filesystem assertions shared by tests in more
// than one package. It lives under the repo-root internal/ tree so the Go
// compiler blocks imports from outside this module.
//
// This package must only be imported from *_test.go files.
package testutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// AssertGone fails unless path is absent, which os.Stat reports as
// os.ErrNotExist. assert.NoFileExists is the shorter spelling but it treats a
// directory at path, and any other Lstat error, as absence, so a test proving
// that a cleanup step ran would pass on a path that is still there.
func AssertGone(t *testing.T, path string, msgAndArgs ...any) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist, msgAndArgs...)
}
