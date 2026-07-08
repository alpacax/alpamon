package runner

import (
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestResolveShell(t *testing.T) {
	valid := []string{"/custom/shell", "/bin/bash"}

	t.Run("empty requested falls back to default", func(t *testing.T) {
		shell, args := resolveShell("", valid)
		assert.Equal(t, utils.DefaultShell(), shell)
		assert.Equal(t, utils.DefaultShellArgs(), args)
	})

	t.Run("valid requested is used with no args", func(t *testing.T) {
		shell, args := resolveShell("/custom/shell", valid)
		assert.Equal(t, "/custom/shell", shell)
		assert.Nil(t, args)
	})

	t.Run("invalid requested falls back to default", func(t *testing.T) {
		shell, args := resolveShell("/not/listed", valid)
		assert.Equal(t, utils.DefaultShell(), shell)
		assert.Equal(t, utils.DefaultShellArgs(), args)
	})
}
