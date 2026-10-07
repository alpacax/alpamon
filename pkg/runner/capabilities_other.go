//go:build !linux && !darwin

package runner

// fileExecCompiled is false where the file lane declines every command with
// FILE_EXEC_UNSUPPORTED.
const fileExecCompiled = false
