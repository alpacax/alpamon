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

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, os.WriteFile(outsideFile, []byte("data"), 0644))

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, bulk, recursive, err := handler.parsePaths(homeDir, []string{outsideFile})
	require.NoError(t, err, "parsePaths returned error after guard removal")
	assert.False(t, bulk, "bulk = true, want false for single path")
	assert.False(t, recursive, "recursive = true, want false for file")
	require.Len(t, paths, 1)
	assert.Equal(t, filepath.Clean(outsideFile), paths[0], "path")
}

// TestFileHandler_parsePaths_Windows_InsideHome is the regression guard:
// the common case (path inside home) must keep working after the fix.
func TestFileHandler_parsePaths_Windows_InsideHome(t *testing.T) {
	homeDir := t.TempDir()
	insideFile := filepath.Join(homeDir, "inside.txt")
	require.NoError(t, os.WriteFile(insideFile, []byte("data"), 0644))

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, bulk, _, err := handler.parsePaths(homeDir, []string{insideFile})
	require.NoError(t, err, "parsePaths returned error")
	assert.False(t, bulk, "bulk = true, want false")
	assert.Equal(t, filepath.Clean(insideFile), paths[0], "path")
}

// TestFileHandler_parsePaths_Windows_Tilde verifies that the `~` shortcut
// still expands to the supplied home directory on Windows.
func TestFileHandler_parsePaths_Windows_Tilde(t *testing.T) {
	homeDir := t.TempDir()
	target := filepath.Join(homeDir, "tilde.txt")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0644))

	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	paths, _, _, err := handler.parsePaths(homeDir, []string{"~/tilde.txt"})
	require.NoError(t, err, "parsePaths returned error")
	assert.Equal(t, filepath.Clean(target), paths[0], "path")
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
	require.NoError(t, err, "parsePaths failed for system path %q", hostsPath)
	assert.Equal(t, filepath.Clean(hostsPath), paths[0], "path")
}

// TestFileHandler_parsePaths_Windows_RejectsUnsafeShapes is the security
// hardening regression guard. After #311 removed home containment,
// SanitizePath is the only path-shape gate; these inputs would otherwise
// reach the OS open call running as SYSTEM. parsePaths must reject:
//   - UNC paths (would authenticate to attacker SMB server, NTLM relay)
//   - Local device namespace (raw disk read via \\.\PHYSICALDRIVE0)
//   - Extended-length namespace (\\?\..., canonicalization bypass)
//   - Embedded null bytes (logging vs OS truncation mismatch)
func TestFileHandler_parsePaths_Windows_RejectsUnsafeShapes(t *testing.T) {
	homeDir := t.TempDir()
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)

	rejected := []struct {
		name string
		path string
	}{
		{"UNC path (wire form)", "//evil.attacker.com/share/payload.exe"},
		{"UNC path (native form)", `\\evil.attacker.com\share\payload.exe`},
		{"local device namespace (wire form)", "//./PHYSICALDRIVE0"},
		{"local device namespace (native form)", `\\.\PHYSICALDRIVE0`},
		{"extended-length namespace", `\\?\C:\Windows\System32\config\SAM`},
		{"extended-length UNC", `\\?\UNC\evil\share\x`},
		{"embedded null byte", "/C:/Users/test/file\x00.txt"},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := handler.parsePaths(homeDir, []string{tc.path})
			require.Error(t, err, "parsePaths(%q) expected error, got nil", tc.path)
		})
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
	require.Equal(t, 0, code, "fileDownload returned msg=%q, want code=0", msg)

	// The function mutates args.Path with the native, cleaned absolute form.
	// Asserting on this guards against a SanitizePath regression that drops
	// the drive letter and silently writes to a CWD-relative location.
	assert.Equal(t, filepath.Clean(destPath), args.Path, "args.Path (native form after SanitizePath)")

	written, err := os.ReadFile(destPath)
	require.NoError(t, err, "destination not written")
	assert.Equal(t, "hello", string(written), "contents")
}

// TestFileHandler_fileDownload_Windows_RejectsUnsafeShapes guards the
// write-to-disk path against the same UNC/device/null-byte vectors as
// parsePaths. A wire-format destination must not be able to make alpamon
// open a remote SMB share or a raw device for writing.
func TestFileHandler_fileDownload_Windows_RejectsUnsafeShapes(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)

	rejected := []struct {
		name string
		path string
	}{
		{"UNC destination", "//evil.attacker.com/share/payload.exe"},
		{"device destination", "//./PHYSICALDRIVE0"},
		{"extended-length destination", `\\?\C:\Windows\System32\bad.exe`},
		{"null byte in destination", "/C:/Users/test/file\x00.txt"},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			args := &common.CommandArgs{
				Type:           "text",
				Content:        "x",
				Path:           tc.path,
				Username:       "test",
				AllowOverwrite: true,
			}
			code, msg := handler.fileDownload(context.Background(), args, nil)
			require.NotEqual(t, 0, code, "fileDownload(%q) expected non-zero code, msg=%q", tc.path, msg)
		})
	}
}
