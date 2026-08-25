//go:build windows

package file

import (
	"context"
	"os"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// extractZipAs extracts in-process. Windows has no privilege demotion here, so
// the agent's own rights apply and access control rests on Alpacon RBAC and
// server-side path restrictions alone.
func extractZipAs(_ context.Context, src *os.File, destDir string, _ *syscall.SysProcAttr) error {
	return utils.UnzipFile(src, destDir)
}
