//go:build !windows

package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadValidShellsFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	content := "# comment line\n\n/bin/bash\n  /bin/zsh  \n/usr/bin/fish\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write shells file: %v", err)
	}

	shells := loadValidShellsFrom(path)

	want := []string{"/bin/bash", "/bin/zsh", "/usr/bin/fish"}
	if !reflect.DeepEqual(shells, want) {
		t.Errorf("expected %v, got %v", want, shells)
	}
}

func TestLoadValidShellsFrom_NoPartialMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	if err := os.WriteFile(path, []byte("/bin/bash2\n"), 0o644); err != nil {
		t.Fatalf("failed to write shells file: %v", err)
	}

	shells := loadValidShellsFrom(path)

	want := []string{"/bin/bash2"}
	if !reflect.DeepEqual(shells, want) {
		t.Errorf("expected %v, got %v", want, shells)
	}
}

func TestLoadValidShellsFrom_CommentsAndBlankOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shells")
	if err := os.WriteFile(path, []byte("# only comments\n\n\t\n"), 0o644); err != nil {
		t.Fatalf("failed to write shells file: %v", err)
	}

	if shells := loadValidShellsFrom(path); shells != nil {
		t.Errorf("expected nil for comments/blank-only file, got %v", shells)
	}
}

func TestLoadValidShellsFrom_MissingFile(t *testing.T) {
	shells := loadValidShellsFrom(filepath.Join(t.TempDir(), "does-not-exist"))
	if shells != nil {
		t.Errorf("expected nil for missing file, got %v", shells)
	}
}
