//go:build darwin || windows

package runner

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// collectCommandTimeout bounds a collector's external command, so a hung directory
// service (opendirectoryd, WMI) cannot stall commit and sync.
var collectCommandTimeout = 30 * time.Second

// runCollectCommand returns the command's stdout; tests swap it to fake a failure.
var runCollectCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second // a child left holding stdout must not outlive the kill
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out after %s: %w", name, collectCommandTimeout, err)
	}
	return out, err
}
