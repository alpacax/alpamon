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
// A symlink listed explicitly is followed, so its whole target tree is archived
// even when that tree lives outside the listed path. A symlink met while walking
// is stored as a link entry (target path, not content), so it cannot recurse into
// a cycle and its target is not pulled in. Sockets, FIFOs and device nodes met
// while walking are skipped; listed explicitly, they are an error.
func CreateZip(destPath string, paths []string, recursive bool) (err error) {
	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close zip file: %w", cerr)
		}
	}()

	w := zip.NewWriter(f)
	// Close writes the central directory, so discarding its error would
	// report a truncated archive as a successful one.
	defer func() {
		if cerr := w.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to finalize zip file: %w", cerr)
		}
	}()

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
			if base == string(filepath.Separator) {
				// Base of "/" is "/", which would make every entry name absolute.
				base = ""
			}
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
				if !fi.Mode().IsRegular() {
					// Sockets, FIFOs and device nodes carry nothing to archive,
					// and opening a FIFO blocks until a writer shows up.
					return nil
				}
				return addFileToZip(w, fpath, name, fi)
			})
			if err != nil {
				return err
			}
		} else {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("cannot archive %s: unsupported file type %s", path, info.Mode().Type())
			}
			if err := addFileToZip(w, path, filepath.Base(path), info); err != nil {
				return err
			}
		}
	}

	return nil
}

// newZipEntry opens an entry carrying the source mode bits, which w.Create
// would replace with 0666. Zip archive names use forward slashes (ZIP spec).
func newZipEntry(w *zip.Writer, archiveName string, fi os.FileInfo, method uint16) (io.Writer, error) {
	hdr := &zip.FileHeader{
		Name:     filepath.ToSlash(archiveName),
		Method:   method,
		Modified: fi.ModTime(),
	}
	// Permissions and the link flag only: setuid, setgid and sticky mean
	// nothing in a download and Unzip would hand them to os.OpenFile.
	hdr.SetMode(fi.Mode().Perm() | fi.Mode()&os.ModeSymlink)

	zw, err := w.CreateHeader(hdr)
	if err != nil {
		return nil, fmt.Errorf("failed to create zip entry: %w", err)
	}
	return zw, nil
}

// addSymlinkToZip writes the link target as the entry body with ModeSymlink
// in the mode bits—the zip --symlinks layout.
func addSymlinkToZip(w *zip.Writer, filePath, archiveName string, fi os.FileInfo) error {
	target, err := os.Readlink(filePath)
	if err != nil {
		return fmt.Errorf("failed to read symlink %s: %w", filePath, err)
	}

	zw, err := newZipEntry(w, archiveName, fi, zip.Store)
	if err != nil {
		return err
	}

	if _, err := zw.Write([]byte(target)); err != nil {
		return fmt.Errorf("failed to write zip entry: %w", err)
	}

	return nil
}

func addFileToZip(w *zip.Writer, filePath, archiveName string, fi os.FileInfo) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()

	zw, err := newZipEntry(w, archiveName, fi, zip.Deflate)
	if err != nil {
		return err
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
