//go:build !windows

package file

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

// errCapReader records the last non-EOF read error so it survives broken-pipe overwrites.
type errCapReader struct {
	r   io.Reader
	err error
}

func (e *errCapReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF {
		e.err = err
	}
	return n, err
}

// readFileAs reads a file, using a demoted cat process when privilege demotion is active.
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) (io.ReadCloser, int64, error) {
	if sysProcAttr == nil {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, 0, err
		}
		return f, st.Size(), nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	cmd := exec.CommandContext(ctx, "cat", path)
	cmd.SysProcAttr = sysProcAttr
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start cat: %w", err)
	}
	return rc, st.Size(), nil
}

// writeFileAs streams src to a file, demoting via tee when sysProcAttr is set. Caller owns src.
// path is sanitized by callers via utils.SanitizePath + (Windows) ResolveAndEnsureUnderHome.
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	if sysProcAttr == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644) // lgtm[go/path-injection]
		if err != nil {
			return err
		}
		_, err = io.Copy(f, src)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path) // lgtm[go/path-injection] drop partial write so retry isn't blocked by AllowOverwrite=false
		}
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(path)))
	cmd.SysProcAttr = sysProcAttr
	// Wrap src to preserve its read error even if a subsequent broken-pipe write
	// overwrites it before cmd.Wait collects the goroutine result.
	erc := &errCapReader{r: src}
	cmd.Stdin = erc
	// capture tee stderr so failures surface a real message, not "exit status 1"
	errW := &stderrCap{cap: stderrCapSize}
	cmd.Stderr = errW
	runErr := cmd.Run()

	if runErr != nil || erc.err != nil {
		// lgtm[go/path-injection]: path sanitized via SanitizePath; Windows additionally
		// enforces ResolveAndEnsureUnderHome. Wire input is admin-authenticated.
		_ = os.Remove(path) // lgtm[go/path-injection]
		if runErr != nil {
			var details []string
			if msg := strings.TrimSpace(errW.buf.String()); msg != "" {
				details = append(details, msg)
			}
			if erc.err != nil && erc.err != runErr {
				details = append(details, erc.err.Error())
			}
			if len(details) > 0 {
				return fmt.Errorf("%w: %s", runErr, strings.Join(details, "; "))
			}
			return runErr
		}
		return fmt.Errorf("failed to read source: %w", erc.err)
	}
	return nil
}
