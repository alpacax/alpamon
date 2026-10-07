//go:build linux || darwin

package runner

// fileExecCompiled matches the platforms that build a sealed file and a path
// that reopens the verified descriptor (sealed_file_*.go here, and
// verified_file_*.go in pkg/executor/handlers/common).
const fileExecCompiled = true
