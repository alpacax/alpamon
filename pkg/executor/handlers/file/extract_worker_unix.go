//go:build !windows

package file

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// extractWorkerCommand is the alpamon subcommand that extracts the archive.
// See cmd/alpamon/command/extract.
const extractWorkerCommand = "extract"

// extractZipAs extracts src into destDir. With demotion active the extraction
// happens in a child process carrying the requesting user's credentials, so
// every file and directory it creates belongs to that user and it cannot write
// over a path the user has no rights to. Without demotion it extracts
// in-process, because there is no identity to drop to.
//
// src is handed over as an inherited descriptor, so the worker extracts the
// archive the caller already validated rather than reopening the path.
func extractZipAs(ctx context.Context, src *os.File, destDir string, sysProcAttr *syscall.SysProcAttr) error {
	if sysProcAttr == nil {
		return utils.UnzipFile(src, destDir)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate the alpamon binary: %w", err)
	}

	cmd := exec.CommandContext(ctx, executable, extractWorkerCommand, destDir)
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = src
	status := &stderrCap{cap: stderrCapSize}
	cmd.Stderr = status
	// Nothing here reads the environment, and the worker runs as the
	// requesting user, who could otherwise read the agent's environment out
	// of the worker's own /proc entry.
	cmd.Env = []string{}

	if runErr := cmd.Run(); runErr != nil {
		if msg := strings.TrimSpace(status.buf.String()); msg != "" {
			return fmt.Errorf("%w: %s", runErr, msg)
		}
		return runErr
	}
	return nil
}
