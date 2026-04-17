package register

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const installExeName = "alpamon.exe"

// ensureInstalled makes register work from any download location on
// Windows, mirroring how `apt install alpamon` or `brew install
// alpamon` place the binary before `alpamon register` is run on
// Linux and macOS.
//
// If the current process is already running from the canonical
// install path (%ProgramFiles%\alpamon\alpamon.exe), the function is
// a no-op. Otherwise it copies the current executable there and
// re-executes register with the original arguments, then exits with
// the child's status. The child process sees "already installed" and
// continues to the normal register flow.
func ensureInstalled() (relaunched bool, err error) {
	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("determine current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	target := filepath.Join(installDir(), installExeName)
	if strings.EqualFold(exe, target) {
		return false, nil
	}

	fmt.Printf("Installing alpamon to %s...\n", target)

	if err := os.MkdirAll(filepath.Dir(target), 0); err != nil {
		return false, fmt.Errorf("create install directory: %w%s", err, installErrorHint(err, filepath.Dir(target)))
	}
	if err := copySelf(exe, target); err != nil {
		return false, err
	}

	fmt.Println("Re-running register from the installed location...")
	cmd := exec.Command(target, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	exitCode := 0
	if runErr := cmd.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return true, runErr
		}
	}
	os.Exit(exitCode)
	return true, nil // unreachable
}

// installDir returns %ProgramFiles%\alpamon, or the hardcoded English
// path if ProgramFiles is unset (unlikely but defensive).
func installDir() string {
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		return filepath.Join(pf, "alpamon")
	}
	return `C:\Program Files\alpamon`
}

func copySelf(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create destination (%s): %w%s", dst, err, installErrorHint(err, dst))
	}

	// Roll back the destination on any failure past this point, so a
	// retry doesn't find a truncated alpamon.exe that would then pass
	// the os.Executable() check and skip reinstall.
	success := false
	defer func() {
		if out != nil {
			_ = out.Close()
		}
		if !success {
			_ = os.Remove(dst)
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("write destination: %w", err)
	}

	closeErr := out.Close()
	out = nil
	if closeErr != nil {
		return fmt.Errorf("close destination: %w", closeErr)
	}

	success = true
	return nil
}

// installErrorHint annotates the two error classes users hit most
// often when copying the binary into Program Files:
//   - ACCESS_DENIED: the shell isn't elevated.
//   - SHARING_VIOLATION: the existing alpamon.exe is being held open
//     by a running service; the operator must stop it first.
func installErrorHint(err error, path string) string {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return ""
	}
	switch errno {
	case windows.ERROR_ACCESS_DENIED:
		return "\nHint: run this command from an elevated (Administrator) prompt."
	case windows.ERROR_SHARING_VIOLATION:
		return fmt.Sprintf("\nHint: %s is in use (likely the running alpamon service). Stop it first:\n  sc.exe stop alpamon", path)
	}
	return ""
}
