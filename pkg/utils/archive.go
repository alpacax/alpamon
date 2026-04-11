package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CreateZip creates a zip archive at destPath containing the specified paths.
// If recursive is true and a path is a directory, its contents are included recursively.
func CreateZip(destPath string, paths []string, recursive bool) error {
	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	for _, path := range paths { // lgtm[go/path-injection]: Paths are admin-specified via command protocol
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", path, err)
		}

		if info.IsDir() && recursive {
			baseDir := filepath.Dir(path)
			err = filepath.Walk(path, func(fpath string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fi.IsDir() {
					return nil
				}
				relPath, err := filepath.Rel(baseDir, fpath)
				if err != nil {
					return err
				}
				return addFileToZip(w, fpath, relPath)
			})
			if err != nil {
				return err
			}
		} else {
			if err := addFileToZip(w, path, filepath.Base(path)); err != nil {
				return err
			}
		}
	}

	return nil
}

func addFileToZip(w *zip.Writer, filePath, archiveName string) error {
	f, err := os.Open(filePath) // lgtm[go/path-injection]: Paths are admin-specified via command protocol
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()

	// Use forward slashes in zip archive names (ZIP spec)
	archiveName = filepath.ToSlash(archiveName)

	zw, err := w.Create(archiveName)
	if err != nil {
		return fmt.Errorf("failed to create zip entry: %w", err)
	}

	if _, err := io.Copy(zw, f); err != nil {
		return fmt.Errorf("failed to write zip entry: %w", err)
	}

	return nil
}

// Unzip extracts a zip archive to the specified destination directory.
// It validates that extracted paths stay within the destination (zip slip protection).
func Unzip(src, destDir string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)

		// Zip-slip protection using filepath.Rel (handles root dirs and all platforms)
		rel, err := filepath.Rel(destDir, filepath.Clean(fpath))
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, 0755); err != nil { // lgtm[go/path-injection]: Protected by zip-slip check above
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil { // lgtm[go/path-injection]: Protected by zip-slip check above
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()) // lgtm[go/path-injection]: Protected by zip-slip check above
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			_ = outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		_ = rc.Close()
		_ = outFile.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
