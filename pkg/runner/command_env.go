package runner

import (
	"regexp"
	"slices"
	"strings"
)

// commandEnvRefusedResult names neither the variable nor its value: a value
// can carry a credential, and the requester already knows what it sent.
const commandEnvRefusedResult = "Command refused: its environment sets a variable the agent does not accept"

var posixEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// commandEnvPrefixes and commandEnvExactNames are the platform environment
// list: variables that decide which program a fixed command runs, or what it
// loads, configures or hands control to. The server refuses them too; this
// copy keeps a server that skipped its check from delivering one. Both are
// uppercase and sorted to match testdata/command_env_policy_vectors.json,
// which the tests read. The server's copy is tested against an identical
// file; keeping the two files identical is a review step, since neither
// repository's tests can see the other's.
//
// The list is a floor, not an inventory of every dangerous variable. Proxy,
// trust and resolver variables (HTTPS_PROXY, SSL_CERT_FILE, PIP_INDEX_URL)
// stay off it on purpose.
var (
	commandEnvPrefixes = []string{
		"BASH_FUNC_",
		"DYLD_",
		"GIT_CONFIG_",
		"LD_",
		"LESSKEY",
		"LUA_CPATH_",
		"LUA_INIT_",
		"LUA_PATH_",
	}
	commandEnvExactNames = []string{
		"APPDATA",
		"AWS_CONFIG_FILE",
		"AWS_PAGER",
		"AWS_SHARED_CREDENTIALS_FILE",
		"BASHOPTS",
		"BASH_ENV",
		"BROWSER",
		"BUNDLE_GEMFILE",
		"CLASSPATH",
		"COMSPEC",
		"CORECLR_ENABLE_PROFILING",
		"CORECLR_PROFILER_PATH",
		"COR_ENABLE_PROFILING",
		"COR_PROFILER",
		"COR_PROFILER_PATH",
		"DBUS_SESSION_BUS_ADDRESS",
		"DBUS_SYSTEM_BUS_ADDRESS",
		"DOTNET_STARTUP_HOOKS",
		"EDITOR",
		"ENV",
		"EXINIT",
		"FCEDIT",
		"FPATH",
		"GCONV_PATH",
		"GEM_HOME",
		"GEM_PATH",
		"GIT_ALLOW_PROTOCOL",
		"GIT_ASKPASS",
		"GIT_COMMON_DIR",
		"GIT_DIR",
		"GIT_EDITOR",
		"GIT_EXEC_PATH",
		"GIT_EXTERNAL_DIFF",
		"GIT_PAGER",
		"GIT_PROXY_COMMAND",
		"GIT_SEQUENCE_EDITOR",
		"GIT_SSH",
		"GIT_SSH_COMMAND",
		"GIT_TEMPLATE_DIR",
		"GIT_WORK_TREE",
		"GNUPGHOME",
		"HOME",
		"HOMEDRIVE",
		"HOMEPATH",
		"IFS",
		"JAVA_TOOL_OPTIONS",
		"JDK_JAVA_OPTIONS",
		"KUBECONFIG",
		"KUBECTL_EXTERNAL_DIFF",
		"KUBE_EDITOR",
		"LESS",
		"LESSCLOSE",
		"LESSEDIT",
		"LESSOPEN",
		"LIBMYSQL_PLUGINS",
		"LIBMYSQL_PLUGIN_DIR",
		"LUA_CPATH",
		"LUA_INIT",
		"LUA_PATH",
		"MANPAGER",
		"NODE_OPTIONS",
		"NODE_PATH",
		"NPM_CONFIG_ALLOW_DIRECTORY",
		"NPM_CONFIG_ALLOW_FILE",
		"NPM_CONFIG_ALLOW_GIT",
		"NPM_CONFIG_ALLOW_REMOTE",
		"NPM_CONFIG_ALLOW_SCRIPTS",
		"NPM_CONFIG_BROWSER",
		"NPM_CONFIG_CALL",
		"NPM_CONFIG_DANGEROUSLY_ALLOW_ALL_SCRIPTS",
		"NPM_CONFIG_EDITOR",
		"NPM_CONFIG_GIT",
		"NPM_CONFIG_GLOBALCONFIG",
		"NPM_CONFIG_IGNORE_SCRIPTS",
		"NPM_CONFIG_INIT_MODULE",
		"NPM_CONFIG_NODE_GYP",
		"NPM_CONFIG_NODE_OPTIONS",
		"NPM_CONFIG_PACKAGE",
		"NPM_CONFIG_PREFIX",
		"NPM_CONFIG_SCRIPT_SHELL",
		"NPM_CONFIG_SHELL",
		"NPM_CONFIG_STRICT_ALLOW_SCRIPTS",
		"NPM_CONFIG_USERCONFIG",
		"NPM_CONFIG_VIEWER",
		"NULLCMD",
		"OPENSSL_CONF",
		"OPENSSL_CONF_INCLUDE",
		"OPENSSL_ENGINES",
		"OPENSSL_MODULES",
		"PAGER",
		"PATH",
		"PATHEXT",
		"PERL5DB",
		"PERL5LIB",
		"PERL5OPT",
		"PERLLIB",
		"PHPRC",
		"PHP_INI_SCAN_DIR",
		"PIP_CONFIG_FILE",
		"PIP_EDITOR",
		"PIP_PYTHON",
		"PROMPT_COMMAND",
		"PS4",
		"PSMODULEPATH",
		"PSQLRC",
		"PYTHONBREAKPOINT",
		"PYTHONHOME",
		"PYTHONINSPECT",
		"PYTHONPATH",
		"PYTHONSTARTUP",
		"PYTHONUSERBASE",
		"PYTHONWARNINGS",
		"READNULLCMD",
		"RSYNC_CONNECT_PROG",
		"RSYNC_RSH",
		"RSYNC_SHELL",
		"RUBYGEMS_GEMDEPS",
		"RUBYLIB",
		"RUBYOPT",
		"SHELL",
		"SHELLOPTS",
		"SSH_ASKPASS",
		"SUDO_ASKPASS",
		"SUDO_EDITOR",
		"SUDO_UID",
		"SVN_SSH",
		"SYSTEMD_EDITOR",
		"SYSTEMD_PAGER",
		"SYSTEMD_PAGERSECURE",
		"TAR_OPTIONS",
		"USERPROFILE",
		"VIMINIT",
		"VIMRUNTIME",
		"VISUAL",
		"XDG_CONFIG_DIRS",
		"XDG_CONFIG_HOME",
		"ZDOTDIR",
		"_JAVA_OPTIONS",
	}
)

// commandEnvRefused reports whether a command's caller-supplied env must not be
// applied: a key that is not a POSIX variable name, a key on the platform list,
// or a value that begins with "()", whatever its key, since an unpatched bash
// imports that form as a function from any variable. Keys are compared
// uppercased, which also covers Windows, where they are case-insensitive.
//
// Only the caller's env is checked. The agent's own defaults are not, so the
// list may name PATH or HOME without refusing a command that sets neither.
func commandEnvRefused(env map[string]string) bool {
	for key, value := range env {
		if !posixEnvName.MatchString(key) ||
			strings.HasPrefix(value, "()") ||
			isListedEnvName(strings.ToUpper(key)) {
			return true
		}
	}
	return false
}

func isListedEnvName(upper string) bool {
	if slices.Contains(commandEnvExactNames, upper) {
		return true
	}
	return slices.ContainsFunc(commandEnvPrefixes, func(prefix string) bool {
		return strings.HasPrefix(upper, prefix)
	})
}
