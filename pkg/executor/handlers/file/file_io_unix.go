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

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
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
	cmd.Env, err = utils.ProcessChildEnvironment(sysProcAttr)
	if err != nil {
		return nil, 0, err
	}
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start cat: %w", err)
	}
	return rc, st.Size(), nil
}

// firstMissingAncestor returns the highest ancestor of dir that mkdir -p would create,
// or "" when dir exists or its state is unknown.
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
	env, err := utils.ProcessChildEnvironment(sysProcAttr)
	if err != nil {
		return
	}
	cmd.Env = env
	_ = cmd.Run()
}

// removeCreatedDirsAsRequester walks from parentDir up to createdRoot, running a
// non-recursive rmdir for each directory with the requester's credentials. It can
// therefore remove only empty directories the requester could remove itself; if
// the path changes underneath it, that bound still holds, not the exact directory.
// createdRoot must be parentDir or an ancestor of it.
// Cleanup survives cancellation, skips absent directories, and stops on other failures.
func removeCreatedDirsAsRequester(ctx context.Context, parentDir, createdRoot string, sysProcAttr *syscall.SysProcAttr) {
	if createdRoot == "" || !filepath.IsAbs(parentDir) {
		return
	}
	env, err := utils.ProcessChildEnvironment(sysProcAttr)
	if err != nil {
		log.Warn().Err(err).Str("path", parentDir).Msg("Skipped cleanup after failed write: cannot resolve the requester's environment")
		return
	}
	for dir := parentDir; ; dir = filepath.Dir(dir) {
		cmd := exec.CommandContext(context.WithoutCancel(ctx), "rmdir", "--", dir)
		cmd.SysProcAttr = sysProcAttr
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			// Check as the requester without depending on localized rmdir messages.
			// Include -L so a dangling symlink is not treated as an absent directory.
			check := exec.CommandContext(context.WithoutCancel(ctx), "sh", "-c", `! test -e "$1" && ! test -L "$1" || exit 1
parent=${1%/*}
while test -n "$parent"; do
  if test -e "$parent" || test -L "$parent"; then
    test -d "$parent" && test -x "$parent" || exit 1
  fi
  parent=${parent%/*}
done`, "sh", dir)
			check.SysProcAttr = sysProcAttr
			check.Env = env
			if check.Run() != nil {
				log.Warn().Err(err).Str("path", dir).Str("output", strings.TrimSpace(string(output))).Msg("Failed to remove directory after failed write")
				return
			}
		}
		if dir == createdRoot {
			return
		}
	}
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
	// Only a target this call created may be removed on failure, and only under the
	// requester's own permissions, never as root--see removeAsRequester and the script's own rm -f.
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
	env, err := utils.ProcessChildEnvironment(sysProcAttr)
	if err != nil {
		return err
	}
	cmd.Env = env
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
		removeCreatedDirsAsRequester(ctx, parentDir, createdRoot, sysProcAttr)
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
