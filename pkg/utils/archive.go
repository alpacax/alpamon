package utils

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errNotRegular = errors.New("not a regular file")

// SkippedEntry is a path left out of the archive, with the reason it was left
// out. Everything else was archived.
type SkippedEntry struct {
	Path   string
	Reason error
}

// unreadable separates a source that cannot be opened, which costs one entry,
// from a failure once the entry is already being written, which costs the whole
// archive. It carries the cause unchanged so the reported reason stays readable.
type unreadable struct{ error }

func (u unreadable) Unwrap() error { return u.error }

// CreateZip creates a zip archive at destPath containing the specified paths.
// If recursive is true and a path is a directory, its contents are included recursively.
// A symlink listed explicitly is followed, so its whole target tree is archived
// even when that tree lives outside the listed path. A symlink met while walking
// is stored as a link entry (target path, not content), so it cannot recurse into
// a cycle and its target is not pulled in. Sockets, FIFOs and device nodes are
// never archived, wherever they are found.
//
// A listed path that cannot be opened, or that is not a regular file, is left
// out and reported in skipped, so one bad path does not cost the user the rest
// of the archive. A failure to write the archive itself returns an error, and so
// does a read that fails once an entry is already being written. An archive that
// holds nothing while something was skipped is an error too: an empty archive is
// a failed request, not a partial one.
func CreateZip(destPath string, paths []string, recursive bool) (skipped []SkippedEntry, err error) {
	note := func(path string, reason error) {
		// A PathError repeats the path the entry already carries, so keep
		// the cause on its own and let the caller pair the two.
		var perr *os.PathError
		if errors.As(reason, &perr) {
			reason = perr.Err
		}
		skipped = append(skipped, SkippedEntry{Path: path, Reason: reason})
	}
	// skip records a source that could not be opened and reports whether err
	// was one, so both branches agree on what costs a single entry.
	skip := func(path string, err error) bool {
		var u unreadable
		if !errors.As(err, &u) {
			return false
		}
		note(path, u.error)
		return true
	}

	// A caller keys off success, so an archive that ended up holding nothing
	// must not be handed over as one.
	archived := false

	f, err := os.Create(destPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create zip file: %w", err)
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
			note(path, err)
			continue
		}

		if info.IsDir() && recursive {
			// filepath.Walk lstats its root and would not descend into a
			// symlinked directory, so resolve the explicitly requested path.
			root, err := filepath.EvalSymlinks(path)
			if err != nil {
				note(path, err)
				continue
			}
			base := filepath.Base(path)
			if base == string(filepath.Separator) {
				// Base of "/" is "/", which would make every entry name absolute.
				base = ""
			}
			err = filepath.Walk(root, func(fpath string, fi os.FileInfo, err error) error {
				if err != nil {
					// Walk hands over the directory it could not read and
					// carries on with its siblings once this returns nil.
					note(fpath, err)
					return nil
				}
				if fi.IsDir() {
					return nil
				}
				relPath, err := filepath.Rel(root, fpath)
				if err != nil {
					return err
				}
				name := filepath.Join(base, relPath)
				switch {
				case fi.Mode()&os.ModeSymlink != 0:
					err = addSymlinkToZip(w, fpath, name, fi)
				case !fi.Mode().IsRegular():
					// Sockets, FIFOs and device nodes carry nothing to archive,
					// and opening a FIFO blocks until a writer shows up.
					return nil
				default:
					err = addFileToZip(w, fpath, name, fi)
				}
				if skip(fpath, err) {
					return nil
				}
				if err != nil {
					return err
				}
				archived = true
				return nil
			})
			if err != nil {
				return skipped, err
			}
		} else {
			if !info.Mode().IsRegular() {
				// Failing here would cost the user every path listed alongside it.
				note(path, errNotRegular)
				continue
			}
			err := addFileToZip(w, path, filepath.Base(path), info)
			if skip(path, err) {
				continue
			}
			if err != nil {
				return skipped, err
			}
			archived = true
		}
	}

	if !archived && len(skipped) > 0 {
		// Every path was skipped, so this is the all-or-nothing failure in the
		// other direction: an empty archive that reports a finished download.
		return skipped, fmt.Errorf("nothing could be archived, skipped %d path(s): %w",
			len(skipped), skipped[0].Reason)
	}

	return skipped, nil
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
		return unreadable{err}
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
		return unreadable{err}
	}
	defer func() { _ = f.Close() }()

	zw, err := newZipEntry(w, archiveName, fi, zip.Deflate)
	if err != nil {
		return err
	}

	if _, err := io.Copy(zw, f); err != nil {
		// A read failing here has already written a partial entry that
		// archive/zip cannot take back, so it ends the archive rather than
		// leaving a silently truncated file in it.
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
//
// A link entry—the target path as the body with ModeSymlink set, the layout
// CreateZip writes—comes back as a real symlink, except on a host that makes
// no links, where the entry is dropped rather than failing the whole
// extraction or landing as a file holding the target path.
//
// Nothing may leave destDir: an escaping entry name is rejected, so is a link
// target that resolves outside, and no entry is written through a link, since
// one an earlier entry created—or one already sitting in destDir—turns a name
// that passes into a route out.
func UnzipReader(r *zip.ReadCloser, destDir string) error {
	// Comparing against destDir unresolved reads an extraction that merely
	// goes through a link as an escape, which is every extraction under /tmp
	// on darwin.
	root, err := filepath.EvalSymlinks(destDir)
	if err != nil {
		return fmt.Errorf("failed to resolve destination directory: %w", err)
	}

	for _, f := range r.File {
		fpath := filepath.Join(root, f.Name)
		if !isInside(root, fpath) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := mkdirAllInside(root, fpath, f.Name); err != nil {
				return err
			}
			continue
		}

		if err := mkdirAllInside(root, filepath.Dir(fpath), f.Name); err != nil {
			return err
		}

		if f.Mode()&os.ModeSymlink != 0 {
			if err := extractSymlink(f, root, fpath); err != nil {
				return err
			}
			continue
		}

		if err := extractFile(f, fpath); err != nil {
			return err
		}
	}

	return nil
}

// isInside reports whether path stays within root.
func isInside(root, path string) bool {
	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// mkdirAllInside walks dir one component at a time because os.MkdirAll follows
// a symlink, which would let a link extracted earlier, or one already sitting
// in destDir, put the entries below it outside root.
func mkdirAllInside(root, dir, name string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return fmt.Errorf("illegal file path in zip: %s", name)
	}
	if rel == "." {
		return nil
	}

	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		fi, err := os.Lstat(current)
		if os.IsNotExist(err) {
			// Commands run on a worker pool, so a second extraction may
			// create the directory first. Losing that race is not a failure,
			// but the check below still has to see what landed.
			if err := os.Mkdir(current, 0755); err != nil && !os.IsExist(err) {
				return err
			}
			fi, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("illegal link target in zip: %s is written through a symlink", name)
		}
	}

	return nil
}

// maxSymlinkTarget is longer than any platform's path limit, so a body past it
// is a malformed entry rather than a target worth reading into memory.
const maxSymlinkTarget = 4096

// extractSymlink restores a link entry, refusing a target that leaves root.
// The mirror of addSymlinkToZip.
func extractSymlink(f *zip.File, root, fpath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(rc, maxSymlinkTarget+1))
	_ = rc.Close()
	if err != nil {
		return err
	}
	if len(body) > maxSymlinkTarget {
		return fmt.Errorf("illegal link target in zip: %s exceeds %d bytes", f.Name, maxSymlinkTarget)
	}

	target := string(body)
	if !isValidLinkTarget(root, fpath, target) {
		return fmt.Errorf("illegal link target in zip: %s -> %s", f.Name, target)
	}

	// os.Symlink refuses an existing path where a regular entry would have
	// truncated it, so clear the way first and keep the two kinds symmetric.
	if err := os.Remove(fpath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := os.Symlink(target, fpath); err != nil {
		if symlinkUnsupported(err) {
			return nil
		}
		return err
	}

	return nil
}

// isValidLinkTarget rejects an empty or absolute target, and a relative one
// that resolves outside root. Zip entries carry slash-separated paths whatever
// wrote them, so a leading slash is absolute on every platform.
func isValidLinkTarget(root, fpath, target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || filepath.IsAbs(target) {
		return false
	}
	return isInside(root, filepath.Join(filepath.Dir(fpath), filepath.FromSlash(target)))
}

// extractFile writes a regular entry. The mirror of addFileToZip.
func extractFile(f *zip.File, fpath string) error {
	// os.OpenFile would write through a link sitting at the path: the last
	// component, the one mkdirAllInside does not cover.
	if fi, err := os.Lstat(fpath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(fpath); err != nil {
			return err
		}
	}

	// Perm only: extraction runs in the alpamon process, which is root on a
	// normal install, so setuid, setgid and sticky off an entry would land on
	// a root-owned file. newZipEntry drops the same bits on the way in.
	outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
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

	return err
}
