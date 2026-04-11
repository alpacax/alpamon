package utils

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateZip_SingleFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(src, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "out.zip")
	if err := CreateZip(dest, []string{src}, false); err != nil {
		t.Fatalf("CreateZip() error: %v", err)
	}

	r, err := zip.OpenReader(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	if len(r.File) != 1 {
		t.Fatalf("expected 1 file in zip, got %d", len(r.File))
	}
	if r.File[0].Name != "hello.txt" {
		t.Errorf("expected entry name hello.txt, got %s", r.File[0].Name)
	}
}

func TestCreateZip_RecursiveDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "mydir", "sub")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mydir", "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "b.txt"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "out.zip")
	if err := CreateZip(dest, []string{filepath.Join(dir, "mydir")}, true); err != nil {
		t.Fatalf("CreateZip() error: %v", err)
	}

	r, err := zip.OpenReader(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	if len(r.File) != 2 {
		t.Fatalf("expected 2 files in zip, got %d", len(r.File))
	}
}

func TestCreateZip_BulkMultiplePaths(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one.txt")
	f2 := filepath.Join(dir, "two.txt")
	if err := os.WriteFile(f1, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("2"), 0644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "out.zip")
	if err := CreateZip(dest, []string{f1, f2}, true); err != nil {
		t.Fatalf("CreateZip() error: %v", err)
	}

	r, err := zip.OpenReader(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	if len(r.File) != 2 {
		t.Fatalf("expected 2 files in zip, got %d", len(r.File))
	}
}

func TestUnzip(t *testing.T) {
	dir := t.TempDir()

	// Create a zip with a file and subdirectory
	zipPath := filepath.Join(dir, "test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	zw, _ := w.Create("root.txt")
	_, _ = zw.Write([]byte("root"))
	zw, _ = w.Create("sub/nested.txt")
	_, _ = zw.Write([]byte("nested"))
	_ = w.Close()
	_ = f.Close()

	extractDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Unzip(zipPath, extractDir); err != nil {
		t.Fatalf("Unzip() error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(extractDir, "root.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "root" {
		t.Errorf("root.txt content = %q, want %q", content, "root")
	}

	content, err = os.ReadFile(filepath.Join(extractDir, "sub", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "nested" {
		t.Errorf("nested.txt content = %q, want %q", content, "nested")
	}
}

func TestUnzip_ZipSlipRejected(t *testing.T) {
	dir := t.TempDir()

	// Create a malicious zip with path traversal
	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	zw, _ := w.Create("../../etc/passwd")
	_, _ = zw.Write([]byte("malicious"))
	_ = w.Close()
	_ = f.Close()

	extractDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		t.Fatal(err)
	}

	err = Unzip(zipPath, extractDir)
	if err == nil {
		t.Fatal("expected zip-slip rejection error")
	}
}

func TestCreateZipAndUnzip_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Create source files
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("aaa"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("bbb"), 0644); err != nil {
		t.Fatal(err)
	}

	// Zip
	zipPath := filepath.Join(dir, "archive.zip")
	if err := CreateZip(zipPath, []string{srcDir}, true); err != nil {
		t.Fatal(err)
	}

	// Unzip
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Unzip(zipPath, outDir); err != nil {
		t.Fatal(err)
	}

	// Verify round-trip
	content, err := os.ReadFile(filepath.Join(outDir, "src", "a.txt"))
	if err != nil {
		t.Fatalf("a.txt not found after round-trip: %v", err)
	}
	if string(content) != "aaa" {
		t.Errorf("a.txt = %q, want %q", content, "aaa")
	}

	content, err = os.ReadFile(filepath.Join(outDir, "src", "sub", "b.txt"))
	if err != nil {
		t.Fatalf("sub/b.txt not found after round-trip: %v", err)
	}
	if string(content) != "bbb" {
		t.Errorf("sub/b.txt = %q, want %q", content, "bbb")
	}
}
