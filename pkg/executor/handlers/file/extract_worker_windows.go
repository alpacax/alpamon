//go:build windows

package file

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// extractZipAs extracts in-process. Windows has no privilege demotion here, so
// the agent's own rights apply and access control rests on Alpacon RBAC and
// server-side path restrictions alone.
func extractZipAs(_ context.Context, srcPath, destDir string, _ *syscall.SysProcAttr) error {
	var status bytes.Buffer
	if utils.RunExtractWorker(srcPath, destDir, &status) != 0 {
		if msg := strings.TrimSpace(status.String()); msg != "" {
			return errors.New(msg)
		}
		return errors.New("extraction failed without reporting a reason")
	}
	return nil
}
