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
// Explicitly listed paths are followed if they are symlinks; symlinks met while
// walking are stored as link entries (target path, not content), so cycles cannot
// recurse and out-of-tree targets are not pulled in.
func CreateZip(destPath string, paths []string, recursive bool) error {
	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", path, err)
		}

		if info.IsDir() && recursive {
			// filepath.Walk lstats its root and would not descend into a
			// symlinked directory, so resolve the explicitly requested path.
			root, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("failed to resolve %s: %w", path, err)
			}
			base := filepath.Base(path)
			err = filepath.Walk(root, func(fpath string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fi.IsDir() {
					return nil
				}
				relPath, err := filepath.Rel(root, fpath)
				if err != nil {
					return err
				}
				name := filepath.Join(base, relPath)
				if fi.Mode()&os.ModeSymlink != 0 {
					return addSymlinkToZip(w, fpath, name, fi)
				}
				return addFileToZip(w, fpath, name)
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

// addSymlinkToZip writes the link target as the entry body with ModeSymlink
// in the mode bits—the zip --symlinks layout.
func addSymlinkToZip(w *zip.Writer, filePath, archiveName string, fi os.FileInfo) error {
	target, err := os.Readlink(filePath)
	if err != nil {
		return fmt.Errorf("failed to read symlink %s: %w", filePath, err)
	}

	hdr := &zip.FileHeader{
		Name:   filepath.ToSlash(archiveName),
		Method: zip.Store,
	}
	hdr.SetMode(fi.Mode())

	zw, err := w.CreateHeader(hdr)
	if err != nil {
		return fmt.Errorf("failed to create zip entry: %w", err)
	}

	if _, err := zw.Write([]byte(target)); err != nil {
		return fmt.Errorf("failed to write zip entry: %w", err)
	}

	return nil
}

func addFileToZip(w *zip.Writer, filePath, archiveName string) error {
	f, err := os.Open(filePath)
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
	return UnzipReader(r, destDir)
}

// UnzipReader extracts an already-opened zip into destDir. Caller owns r.
// Used when the caller has pre-validated the same handle to close TOCTOU windows.
func UnzipReader(r *zip.ReadCloser, destDir string) error {
	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)

		// Zip-slip protection using filepath.Rel (handles root dirs and all platforms)
		rel, err := filepath.Rel(destDir, filepath.Clean(fpath))
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
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
