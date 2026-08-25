//go:build !windows

package file

import (
	"bytes"
	"context"
	"errors"
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

// extractZipAs extracts the archive at srcPath into destDir. With demotion
// active the work happens in a child process carrying the requesting user's
// credentials, so every file and directory it creates belongs to that user, it
// cannot write over a path the user has no rights to, and the source open and
// unlink resolve as the user rather than as the agent. Without demotion it
// runs the same code in-process, because there is no identity to drop to.
//
// srcPath is passed rather than an open descriptor on purpose: opening it here
// would make the agent resolve a path the requesting user controls, and
// O_NOFOLLOW only covers the final component.
func extractZipAs(ctx context.Context, srcPath, destDir string, sysProcAttr *syscall.SysProcAttr) error {
	if sysProcAttr == nil {
		var status bytes.Buffer
		if utils.RunExtractWorker(srcPath, destDir, &status) != 0 {
			return errors.New(strings.TrimSpace(status.String()))
		}
		return nil
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate the alpamon binary: %w", err)
	}

	cmd := exec.CommandContext(ctx, executable, extractWorkerCommand, srcPath, destDir)
	cmd.SysProcAttr = sysProcAttr
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
