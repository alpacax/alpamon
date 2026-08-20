package command

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlatformCommands(t *testing.T) {
	var names []string
	for _, cmd := range platformCommands() {
		names = append(names, cmd.Name())
	}

	if runtime.GOOS == "windows" {
		assert.Empty(t, names)
	} else {
		assert.Equal(t, []string{"tunnel-daemon"}, names)
	}
}
