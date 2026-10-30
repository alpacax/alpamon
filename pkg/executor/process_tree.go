package executor

import "os/exec"

// commandCleaner is the process-tree cleanup contract shared by the per-platform commandCleanup types.
// Each platform file asserts *commandCleanup satisfies it, so an afterStart/cancel/close signature that
// drifts between process_tree_unix.go and process_tree_windows.go fails that platform's build early.
type commandCleaner interface {
	afterStart(*exec.Cmd) error
	cancel(*exec.Cmd) (cleanupOutcome, error)
	close() error
}

// cleanupOutcome reports what one cancel did, for the single log line runCommand writes after it.
type cleanupOutcome struct {
	survivors []int
	// assigned: the tree was confined where cancel can reach it—the Windows job object, or a
	// Unix process group the child leads.
	assigned bool
	// active is the number of live job members just before the kill; always 0 on Unix.
	active uint32
	// rootKilled: the kill reached a live process (Windows: the root; Unix: any member of its group).
	rootKilled bool
}

// killedAny reports whether the cancel terminated anything that was still running.
func (o cleanupOutcome) killedAny() bool {
	return o.rootKilled || o.active > 0
}
