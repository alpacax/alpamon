package executor

import "os/exec"

// commandCleaner is the process-tree cleanup contract shared by the per-platform commandCleanup types.
// Each platform file asserts *commandCleanup satisfies it, so an afterStart/cancel/close signature that
// drifts between process_tree_unix.go and process_tree_windows.go fails that platform's build early.
type commandCleaner interface {
	afterStart(*exec.Cmd) error
	cancel(*exec.Cmd) error
	close() error
}
