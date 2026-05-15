//go:build windows

// These tests document the post-#311 Windows file-handler behavior:
// the previous home-directory containment was removed because alpamon
// runs as SYSTEM on Windows (privilege demotion is stubbed), so the
// lexical guard provided no real protection. Access control is now
// delegated to Alpacon RBAC and the OS service account; see
// docs/windows.md "Permissions and identity".

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
)

// TestFileHandler_parsePaths_Windows_OutsideHome verifies the fix for #311:
// requesting a file outside the operator's home directory used to fail with
// "path escapes home directory" via the removed ResolveAndEnsureUnderHome
// guard. After the fix, parsePaths must return the sanitized absolute path
// without error.
func TestFileHandler_parsePaths_Windows_OutsideHome(t *testing.T) {
	homeDir := t.TempDir()
	outsideDir := t.TempDir() // separate TempDir, not under homeDir
	outsideFile := filepath.Join(outsideDir, "external.txt")
	if err := os.WriteFile(outsideFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, bulk, recursive, err := handler.parsePaths(homeDir, []string{outsideFile})
	if err != nil {
		t.Fatalf("parsePaths returned error after guard removal: %v", err)
	}
	if bulk {
		t.Errorf("bulk = true, want false for single path")
	}
	if recursive {
		t.Errorf("recursive = true, want false for file")
	}
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1", len(paths))
	}
	if want := filepath.Clean(outsideFile); paths[0] != want {
		t.Errorf("got path %q, want %q", paths[0], want)
	}
}

// TestFileHandler_parsePaths_Windows_InsideHome is the regression guard:
// the common case (path inside home) must keep working after the fix.
func TestFileHandler_parsePaths_Windows_InsideHome(t *testing.T) {
	homeDir := t.TempDir()
	insideFile := filepath.Join(homeDir, "inside.txt")
	if err := os.WriteFile(insideFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, bulk, _, err := handler.parsePaths(homeDir, []string{insideFile})
	if err != nil {
		t.Fatalf("parsePaths returned error: %v", err)
	}
	if bulk {
		t.Errorf("bulk = true, want false")
	}
	if want := filepath.Clean(insideFile); paths[0] != want {
		t.Errorf("got path %q, want %q", paths[0], want)
	}
}

// TestFileHandler_parsePaths_Windows_Tilde verifies that the `~` shortcut
// still expands to the supplied home directory on Windows.
func TestFileHandler_parsePaths_Windows_Tilde(t *testing.T) {
	homeDir := t.TempDir()
	target := filepath.Join(homeDir, "tilde.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, _, _, err := handler.parsePaths(homeDir, []string{"~/tilde.txt"})
	if err != nil {
		t.Fatalf("parsePaths returned error: %v", err)
	}
	if want := filepath.Clean(target); paths[0] != want {
		t.Errorf("got path %q, want %q", paths[0], want)
	}
}

// TestFileHandler_parsePaths_Windows_SystemRoot is the closest reproduction
// of the original bug: requesting %SystemRoot%\System32\drivers\etc\hosts.
// Before the fix this returned "path escapes home directory"; after the fix
// it must succeed (assuming the standard Windows directory layout).
func TestFileHandler_parsePaths_Windows_SystemRoot(t *testing.T) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Skip("SystemRoot env var not set")
	}
	hostsPath := filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts")
	if _, err := os.Stat(hostsPath); err != nil {
		t.Skipf("system hosts file not accessible: %v", err)
	}

	homeDir := t.TempDir()
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, _, _, err := handler.parsePaths(homeDir, []string{hostsPath})
	if err != nil {
		t.Fatalf("parsePaths failed for system path %q: %v", hostsPath, err)
	}
	if want := filepath.Clean(hostsPath); paths[0] != want {
		t.Errorf("got path %q, want %q", paths[0], want)
	}
}

// TestFileHandler_fileDownload_Windows_OutsideHome exercises the
// browser-to-host write path. Before the fix, fileDownload rejected any
// destination outside the operator's home with "path escapes home directory".
// After the fix, writing to a path outside home succeeds (the write may
// still fail due to OS-level permissions in the wild, but the agent-side
// containment is no longer the blocker).
func TestFileHandler_fileDownload_Windows_OutsideHome(t *testing.T) {
	destDir := t.TempDir()
	destPath := filepath.Join(destDir, "out.txt")
	wireDestPath := utils.ToWirePath(destPath)

	args := &common.CommandArgs{
		Type:           "text",
		Content:        "hello",
		Path:           wireDestPath,
		Username:       "test",
		AllowOverwrite: true,
	}

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	code, msg := handler.fileDownload(context.Background(), args, nil)
	if code != 0 {
		t.Fatalf("fileDownload returned code=%d msg=%q, want code=0", code, msg)
	}

	// The function mutates args.Path with the native, cleaned absolute form.
	// Asserting on this guards against a SanitizePath regression that drops
	// the drive letter and silently writes to a CWD-relative location.
	if want := filepath.Clean(destPath); args.Path != want {
		t.Errorf("args.Path = %q, want %q (native form after SanitizePath)", args.Path, want)
	}

	written, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("destination not written: %v", err)
	}
	if string(written) != "hello" {
		t.Errorf("contents = %q, want %q", string(written), "hello")
	}
}
