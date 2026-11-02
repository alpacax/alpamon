package executor

import "syscall"

// workingDirUsable is never consulted on Windows, which has no verified file lane.
func workingDirUsable(string, *syscall.SysProcAttr) bool { return true }
