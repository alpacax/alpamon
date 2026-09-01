//go:build windows

package file

import (
	"context"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// createArchiveAs builds the archive in-process. Windows has no privilege
// demotion here, so the agent's own rights apply and access control rests on
// Alpacon RBAC and server-side path restrictions alone.
func createArchiveAs(_ context.Context, destPath string, paths []string, recursive bool, _ *syscall.SysProcAttr) (utils.SkippedReport, error) {
	skipped, err := utils.CreateZip(destPath, paths, recursive)
	return utils.SkippedReport{Entries: skipped, Total: len(skipped)}, err
}
