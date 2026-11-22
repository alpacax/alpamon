package shell

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandEnvironment(t *testing.T) {
	for _, name := range []string{"PATH",
		"LD_",
		"LD_FUTURE_OPTION",
		"DYLD_",
		"DYLD_FUTURE_OPTION",
		"GCONV_PATH",
		"BASH_ENV",
		"ENV",
		"BASH_FUNC_",
		"BASH_FUNC_example",
		"SHELLOPTS",
		"BASHOPTS",
		"PROMPT_COMMAND",
		"PS4",
		"IFS",
		"NODE_OPTIONS",
		"NODE_PATH",
		"PYTHONPATH",
		"PYTHONHOME",
		"PYTHONSTARTUP",
		"PERL5LIB",
		"PERL5OPT",
		"PERLLIB",
		"RUBYOPT",
		"RUBYLIB",
		"JAVA_TOOL_OPTIONS",
		"_JAVA_OPTIONS",
		"JDK_JAVA_OPTIONS",
		"DOTNET_STARTUP_HOOKS",
		"CORECLR_PROFILER_PATH",
		"CORECLR_ENABLE_PROFILING",
		"GIT_SSH_COMMAND",
		"GIT_EXEC_PATH",
		"GIT_CONFIG_",
		"GIT_CONFIG_FUTURE_OPTION",
		"HOME",
		"XDG_CONFIG_HOME"} {
		for _, key := range []string{name, strings.ToLower(name), strings.ToUpper(name[:1]) + strings.ToLower(name[1:])} {
			assert.Error(t, validateEnvironment(map[string]string{"FOO_BAR": "1", key: "value"}), key)
		}
		if !strings.HasPrefix(name, "LD_") && !strings.HasPrefix(name, "DYLD_") && !strings.HasPrefix(name, "GIT_CONFIG_") && !strings.HasPrefix(name, "BASH_FUNC_") {
			for _, key := range []string{name + "X", strings.ToLower(name) + "_X"} {
				assert.NoError(t, validateEnvironment(map[string]string{key: "value"}), key)
			}
		}
	}
	for _, key := range []string{"", "1KEY", "FOO-BAR", "FOO=BAR", "FOO BAR", "FOO\n", "ÉNV", "BASH_FUNC_example%%"} {
		assert.Error(t, validateEnvironment(map[string]string{key: "value"}))
	}
}

func TestAllowedEnvironment(t *testing.T) {
	for _, key := range strings.Fields("FOO_BAR _ _key123 LANG TZ TERM http_proxy HTTPS_PROXY PGPASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY PIP_CONFIG_FILE NPM_CONFIG_USERCONFIG PATH_SUFFIX HOME_SUFFIX GIT_CONFIG LD DYLD BASH_FUNC ALPACON_URL PLUGIN_ID PLUGIN_KEY") {
		assert.NoError(t, validateEnvironment(map[string]string{key: "1"}), key)
	}
	assert.NoError(t, validateEnvironment(nil))
	assert.NoError(t, validateEnvironment(map[string]string{}))
}
