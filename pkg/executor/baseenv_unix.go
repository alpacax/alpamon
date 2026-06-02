//go:build !windows

package executor

// processBaseEnv returns the base environment for a command. On Unix it is
// empty: the environment is synthesized deterministically so the child never
// inherits Alpamon's own service environment (USER=root, systemd variables).
func processBaseEnv() map[string]string {
	return map[string]string{}
}

// putEnv sets key=value in env. On Unix environment variable names are
// case-sensitive, so it is a plain assignment.
func putEnv(env map[string]string, key, value string) {
	env[key] = value
}
