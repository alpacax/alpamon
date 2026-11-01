package register

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackgroundAgentEnvironment(t *testing.T) {
	for _, key := range []string{"PLUGIN_KEY", "PLUGIN_TOKEN", "PLUGIN_", "PLUGIN_OTHER_VALUE"} {
		t.Setenv(key, "synthetic-value")
	}
	t.Setenv("ALPAMON_KEEP", "configured-value")
	cmd := backgroundAgentCommand("/bin/sh")
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		assert.False(t, strings.HasPrefix(key, "PLUGIN_"), "unexpected variable %s", key)
	}
	assert.Contains(t, cmd.Env, "ALPAMON_KEEP=configured-value")
	cmd.Args = []string{"/bin/sh", "-c", `printf '%s|%s|%s' "$PLUGIN_KEY" "$PLUGIN_TOKEN" "$ALPAMON_KEEP"`}
	output, err := cmd.Output()
	require.NoError(t, err)
	assert.Equal(t, "||configured-value", string(output))
}
