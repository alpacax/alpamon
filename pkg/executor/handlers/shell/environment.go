package shell

import (
	"errors"
	"regexp"
	"strings"
)

var commandEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateEnvironment(env map[string]string) error {
	for key := range env {
		if !commandEnvName.MatchString(key) {
			return errors.New("invalid command environment name")
		}
		name := strings.ToUpper(key)
		for _, prefix := range []string{"LD_", "DYLD_", "BASH_FUNC_", "GIT_CONFIG_"} {
			if strings.HasPrefix(name, prefix) {
				return errors.New("command environment name is restricted")
			}
		}
		switch name {
		case "BASHOPTS",
			"BASH_ENV",
			"CORECLR_ENABLE_PROFILING",
			"CORECLR_PROFILER_PATH",
			"DOTNET_STARTUP_HOOKS",
			"ENV",
			"GCONV_PATH",
			"GIT_EXEC_PATH",
			"GIT_SSH_COMMAND",
			"HOME",
			"IFS",
			"JAVA_TOOL_OPTIONS",
			"JDK_JAVA_OPTIONS",
			"NODE_OPTIONS",
			"NODE_PATH",
			"PATH",
			"PERL5LIB",
			"PERL5OPT",
			"PERLLIB",
			"PROMPT_COMMAND",
			"PS4",
			"PYTHONHOME",
			"PYTHONPATH",
			"PYTHONSTARTUP",
			"RUBYLIB",
			"RUBYOPT",
			"SHELLOPTS",
			"XDG_CONFIG_HOME",
			"_JAVA_OPTIONS":
			return errors.New("command environment name is restricted")
		}
	}
	return nil
}
