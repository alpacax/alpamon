package utils

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithoutPluginEnvironment(t *testing.T) {
	t.Setenv("PLUGIN_KEY", "synthetic-value")
	t.Setenv("PLUGIN_", "synthetic-value")
	t.Setenv("plugin_lower", "retained-on-unix")
	t.Setenv("ALPAMON_KEEP", "keep")
	env := WithoutPluginEnvironment()
	assert.Contains(t, env, "ALPAMON_KEEP=keep")
	assert.NotContains(t, env, "PLUGIN_KEY=synthetic-value")
	assert.NotContains(t, env, "PLUGIN_=synthetic-value")
	if runtime.GOOS == "windows" {
		assert.NotContains(t, env, "plugin_lower=retained-on-unix")
	} else {
		assert.Contains(t, env, "plugin_lower=retained-on-unix")
	}
}
