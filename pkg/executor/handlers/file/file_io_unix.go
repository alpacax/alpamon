//go:build !windows

package file

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
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

// firstMissingAncestor returns the highest ancestor of dir that mkdir -p would create,
// or "" when dir exists or its state is unknown, so callers never remove a directory they didn't create.
func firstMissingAncestor(dir string) string {
	missing := ""
	cur := dir
	for {
		if _, err := os.Lstat(cur); err == nil {
			return missing
		} else if !os.IsNotExist(err) {
			return ""
		}
		missing = cur
		parent := filepath.Dir(cur)
		if parent == cur {
			return missing
		}
		cur = parent
	}
}

// removeAsRequester unlinks path under the requesting user's own permissions instead of the
// agent's (root), so a symlink swapped into a path component after the caller's Lstat check
// cannot redirect a root-privileged unlink. Run errors are swallowed: rm -f already reports
// success on a missing target, and there is no recovery available from a demoted rm failing.
// context.WithoutCancel is deliberate--context cancellation is one of the ways this cleanup
// path is reached, and the removal must still run even after ctx is done.
func removeAsRequester(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) {
	cmd := exec.CommandContext(context.WithoutCancel(ctx), "rm", "-f", path)
	cmd.SysProcAttr = sysProcAttr
	_ = cmd.Run()
}

// dirTreeIsAllDirs reports whether root and everything under it are plain directories,
// so removing it cannot discard a file a concurrent writer placed there.
func dirTreeIsAllDirs(root string) bool {
	safe := true
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			safe = false
			return filepath.SkipAll
		}
		return nil
	})
	return safe
}

// writeFileAs streams src to a file, demoting via tee when sysProcAttr is set. Caller owns src.
// path must already be absolute: callers sanitize it via utils.SanitizePath, which rejects
// null bytes, UNC/device prefixes, and literal ".." after cleaning.
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("invalid argument: path must be absolute: %s", path)
	}
	// No-op for the absolute path SanitizePath produces; it is the sanitizer shape CodeQL recognizes.
	path = filepath.Clean("/" + path)
	if sysProcAttr == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, src)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path) // drop partial write so retry isn't blocked by AllowOverwrite=false
		}
		return err
	}
	parentDir := filepath.Dir(path)
	createdRoot := firstMissingAncestor(parentDir)
	// Only a target this call creates may be removed on failure: mkdir -p exits 0 on an
	// existing parent, so a tee that fails to open a pre-existing file leaves it untouched,
	// and removing it would delete something the caller never created. When we do remove it,
	// the removal runs inside this same demoted shell, under the requester's real permissions,
	// not later in Go as the agent (root)--which would otherwise let a symlink swapped into a
	// path component redirect a root-privileged unlink.
	_, targetStatErr := os.Lstat(path)
	createdTarget := os.IsNotExist(targetStatErr)
	script := fmt.Sprintf("mkdir -p %s && tee %s > /dev/null", utils.Quote(parentDir), utils.Quote(path))
	if createdTarget {
		script = fmt.Sprintf("mkdir -p %s && { tee %s > /dev/null || { rm -f %s; exit 1; }; }",
			utils.Quote(parentDir), utils.Quote(path), utils.Quote(path))
	}
	// Create parents as the requesting user to preserve filesystem permissions.
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.SysProcAttr = sysProcAttr
	// Wrap src to preserve its read error even if a subsequent broken-pipe write
	// overwrites it before cmd.Wait collects the goroutine result.
	erc := &errCapReader{r: src}
	cmd.Stdin = erc
	// capture tee stderr so failures surface a real message, not "exit status 1"
	errW := &stderrCap{cap: stderrCapSize}
	cmd.Stderr = errW
	runErr := cmd.Run()

	// erc.err is only ever non-nil alongside a non-nil runErr: cmd.Wait returns the stdin-copy
	// goroutine's error on a clean exit, and the process's own exit error otherwise. The
	// fallback after this block guards that invariant instead of relying on it silently.
	if runErr != nil {
		// erc.err alone does not prove tee opened path: a tee that cannot open a pre-existing
		// file still drains stdin to EOF and exits nonzero, so a source read failure can arrive
		// with the target untouched. Only remove it when this call created it, and--same as the
		// rm -f in the script above--under the requester's own permissions, not root's.
		if erc.err != nil && createdTarget {
			if fi, statErr := os.Lstat(path); statErr == nil && !fi.IsDir() {
				removeAsRequester(ctx, path, sysProcAttr)
			}
		}
		if createdRoot != "" && dirTreeIsAllDirs(createdRoot) {
			_ = os.RemoveAll(createdRoot)
		}
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
	if erc.err != nil {
		return fmt.Errorf("failed to read source: %w", erc.err)
	}
	return nil
}
