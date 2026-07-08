//go:build !windows

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadValidShellsFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	content := "# comment line\n\n/bin/bash\n  /bin/zsh  \n/usr/bin/fish\n"
	assert.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	shells := loadValidShellsFrom(path)

	assert.Equal(t, []string{"/bin/bash", "/bin/zsh", "/usr/bin/fish"}, shells)
	assert.NotContains(t, shells, "# comment line")
}

func TestLoadValidShellsFrom_NoPartialMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	assert.NoError(t, os.WriteFile(path, []byte("/bin/bash2\n"), 0o644))

	shells := loadValidShellsFrom(path)

	assert.NotContains(t, shells, "/bin/bash")
	assert.Equal(t, []string{"/bin/bash2"}, shells)
}

func TestLoadValidShellsFrom_MissingFile(t *testing.T) {
	shells := loadValidShellsFrom(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Nil(t, shells)
}
