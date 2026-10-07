//go:build linux || darwin

package runner

// fileExecCompiled matches the platforms that build a sealed file and a path
// that reopens the verified descriptor (sealed_file_*.go, verified_file_*.go).
const fileExecCompiled = true
