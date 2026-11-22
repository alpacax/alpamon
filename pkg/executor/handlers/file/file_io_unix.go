//go:build !windows

package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

var fileHelperCommand = exec.CommandContext

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
	env, err := fileHelperEnvironment(sysProcAttr)
	if err != nil {
		return nil, 0, err
	}
	statArgs := []string{"-L", "-c", "%s", "--", path}
	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		statArgs = []string{"-L", "-f", "%z", "--", path}
	}
	stat := fileHelperCommand(ctx, "/usr/bin/stat", statArgs...)
	stat.SysProcAttr = sysProcAttr
	stat.Env = env
	output, err := stat.Output()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat source file: %w", err)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse source file size: %w", err)
	}
	cmd := fileHelperCommand(ctx, "/bin/cat", "--", path)
	cmd.SysProcAttr = sysProcAttr
	cmd.Env = env
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start cat: %w", err)
	}
	return rc, size, nil
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
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cmd := fileHelperCommand(ctx, "/bin/rm", "-f", path)
	cmd.SysProcAttr = sysProcAttr
	env, err := fileHelperEnvironment(sysProcAttr)
	if err != nil {
		return
	}
	cmd.Env = env
	_ = cmd.Run()
	if ctx.Err() != nil {
		log.Warn().Err(ctx.Err()).Msg("File removal timed out")
	}
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
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	env, err := fileHelperEnvironment(sysProcAttr)
	if err != nil {
		log.Warn().Err(err).Str("path", parentDir).Msg("Skipped cleanup after failed write: cannot resolve the requester's environment")
		return
	}
	for dir := parentDir; ; dir = filepath.Dir(dir) {
		cmd := fileHelperCommand(ctx, "/bin/rmdir", "--", dir)
		cmd.SysProcAttr = sysProcAttr
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			if ctx.Err() != nil {
				log.Warn().Err(ctx.Err()).Msg("Directory cleanup timed out")
				return
			}
			// Check as the requester without depending on localized rmdir messages.
			// Include -L so a dangling symlink is not treated as an absent directory.
			check := fileHelperCommand(ctx, "/bin/sh", "-c", `! test -e "$1" && ! test -L "$1" || exit 1
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
				if ctx.Err() != nil {
					log.Warn().Err(ctx.Err()).Msg("Directory cleanup timed out")
					return
				}
				log.Warn().Err(err).Str("path", dir).Str("output", strings.TrimSpace(string(output))).Msg("Failed to remove directory after failed write")
				return
			}
		}
		if dir == createdRoot {
			return
		}
	}
}

// writeFileAs streams src to a file under the requested credentials. Caller owns src.
// path must already be absolute: callers sanitize it via utils.SanitizePath, which rejects
// null bytes, UNC/device prefixes, and literal ".." after cleaning.
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr, allowOverwrite bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("invalid argument: path must be absolute: %s", path)
	}
	// No-op for the absolute path SanitizePath produces; it is the sanitizer shape CodeQL recognizes.
	path = filepath.Clean("/" + path)
	if os.Geteuid() == 0 && (sysProcAttr == nil || sysProcAttr.Credential == nil || sysProcAttr.Credential.Uid == 0) {
		parent, err := os.Stat(filepath.Dir(path))
		if err == nil && parent.Mode()&os.ModeSticky != 0 && parent.Mode().Perm()&0022 != 0 {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err == nil {
				_, writeErr := io.Copy(f, src)
				closeErr := f.Close()
				if err := errors.Join(writeErr, closeErr); err != nil {
					_ = os.Remove(path)
					return err
				}
				return nil
			}
			if !allowOverwrite || !errors.Is(err, os.ErrExist) {
				return err
			}
			// A root-owned regular entry cannot be replaced by another account in this parent.
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("root transfer requires a root-owned regular file: %s", path)
			}
			if info.Sys().(*syscall.Stat_t).Nlink != 1 {
				return fmt.Errorf("root transfer requires a file with one link: %s", path)
			}
		}
	}
	if sysProcAttr == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(path, transferOpenFlags(allowOverwrite), 0644)
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
	if !allowOverwrite && runtime.GOOS != "darwin" {
		return writeFileExclusiveAs(ctx, path, src, sysProcAttr)
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
	cmd := fileHelperCommand(ctx, "/bin/sh", "-c", script)
	cmd.SysProcAttr = sysProcAttr
	env, err := fileHelperEnvironment(sysProcAttr)
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

// writeFileExclusiveAs publishes a complete download by linking its temporary
// file into place. Both the staging and publication run as the requester.
func writeFileExclusiveAs(ctx context.Context, path string, src io.Reader, attr *syscall.SysProcAttr) error {
	env, err := fileHelperEnvironment(attr)
	if err != nil {
		return err
	}
	run := func(stdin io.Reader, script string, args ...string) ([]byte, error) {
		cmd := fileHelperCommand(ctx, "/bin/sh", append([]string{"-c", script, "sh"}, args...)...)
		cmd.SysProcAttr = attr
		cmd.Env = env
		cmd.Stdin = stdin
		stderr := &stderrCap{cap: stderrCapSize}
		cmd.Stderr = stderr
		output, err := cmd.Output()
		if err != nil && strings.TrimSpace(stderr.buf.String()) != "" {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.buf.String()))
		}
		return output, err
	}

	parent := filepath.Dir(path)
	output, err := run(nil, `mkdir -p -- "$1" && umask 077 && mktemp "$1/.alpamon-download.XXXXXXXXXX"`, parent)
	temp := strings.TrimSuffix(string(output), "\n")
	if temp != "" {
		defer removeAsRequester(ctx, temp, attr)
	}
	if err != nil {
		return err
	}
	if temp == "" {
		return errors.New("mktemp returned no path")
	}

	// Wait for both the input copy and the writer before publishing.
	reader := &errCapReader{r: src}
	_, err = run(reader, `cat > "$1"`, temp)
	if reader.err != nil {
		return fmt.Errorf("failed to read source: %w", reader.err)
	}
	if err != nil {
		return err
	}

	_, err = run(nil, exclusiveLinkScript(), temp, path)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 17 {
		return &os.PathError{Op: "create", Path: path, Err: os.ErrExist}
	}
	return err
}

func exclusiveLinkScript() string {
	command := "link"
	if runtime.GOOS == "linux" {
		command = "ln -T --"
	}
	return `export LC_ALL=C
if message=$(` + command + ` "$1" "$2" 2>&1); then exit 0; fi
case "$message" in *": File exists") exit 17;; esac
printf '%s\n' "$message" >&2
exit 1`
}

// fileHelperEnvironment pins PATH to the system directories, so the mkdir, tee and rm
// that file helper scripts call by name resolve only there.
func fileHelperEnvironment(attr *syscall.SysProcAttr) ([]string, error) {
	env, err := utils.ProcessChildEnvironment(attr)
	for i, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			env[i] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
		}
	}
	return env, err
}

func fileExistsAs(ctx context.Context, path string, attr *syscall.SysProcAttr) (bool, error) {
	if attr == nil {
		return utils.FileExists(path), nil
	}
	return fileTestAs(ctx, path, attr, `test -e "$1"`)
}

func fileIsDirAs(ctx context.Context, path string, attr *syscall.SysProcAttr) (bool, error) {
	if attr == nil {
		info, err := os.Stat(path)
		return err == nil && info.IsDir(), err
	}
	dir, err := fileTestAs(ctx, path, attr, `test -e "$1" || exit 2; test -d "$1"`)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 2 {
		return false, fmt.Errorf("source path is missing or inaccessible: %s", path)
	}
	return dir, err
}

func fileTestAs(ctx context.Context, path string, attr *syscall.SysProcAttr, script string) (bool, error) {
	cmd := fileHelperCommand(ctx, "/bin/sh", "-c", script, "sh", path)
	cmd.SysProcAttr = attr
	env, err := fileHelperEnvironment(attr)
	if err != nil {
		return false, err
	}
	cmd.Env = env
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return err == nil, err
}

func validateTransferDestination(path string, attr *syscall.SysProcAttr) error {
	uid := uint32(os.Geteuid())
	if attr != nil && attr.Credential != nil {
		uid = attr.Credential.Uid
	}
	if uid != 0 {
		return nil
	}
	current := "/"
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/tmp", "/var", "/etc"} {
			if strings.HasPrefix(path, alias+"/") {
				target, err := os.Readlink(alias)
				if err == nil && (target == "private"+alias || target == "/private"+alias) {
					path = "/private" + path
				}
				break
			}
		}
	}
	stickyParent := false
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && (!stickyParent || current == path) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cannot verify root transfer destination %s: %w", current, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("root transfer requires a root-owned destination without symbolic links: %s", current)
		}
		if current == path && info.Mode().IsRegular() && st.Nlink != 1 {
			return fmt.Errorf("root transfer requires a file with one link: %s", current)
		}
		stickyParent = info.IsDir() && info.Mode()&os.ModeSticky != 0 && info.Mode().Perm()&0022 != 0
		if info.Mode().Perm()&0022 != 0 && !stickyParent {
			return fmt.Errorf("root transfer requires a destination writable only by root: %s", current)
		}
	}
	return nil
}
