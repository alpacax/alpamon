//go:build !windows

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadValidShellsFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	content := "# comment line\n\n/bin/bash\n  /bin/zsh  \n/usr/bin/fish\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644), "failed to write shells file")

	shells := loadValidShellsFrom(path)

	want := []string{"/bin/bash", "/bin/zsh", "/usr/bin/fish"}
	assert.Equal(t, want, shells)
}

func TestLoadValidShellsFrom_NoPartialMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	require.NoError(t, os.WriteFile(path, []byte("/bin/bash2\n"), 0o644), "failed to write shells file")

	shells := loadValidShellsFrom(path)

	want := []string{"/bin/bash2"}
	assert.Equal(t, want, shells)
}

func TestLoadValidShellsFrom_CommentsAndBlankOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	require.NoError(t, os.WriteFile(path, []byte("# only comments\n\n\t\n"), 0o644), "failed to write shells file")

	assert.Nil(t, loadValidShellsFrom(path), "expected nil for comments/blank-only file")
}

func TestLoadValidShellsFrom_MissingFile(t *testing.T) {
	shells := loadValidShellsFrom(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Nil(t, shells, "expected nil for missing file")
}
