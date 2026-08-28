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

const (
	// maxSymlinkTarget is past any platform's path limit, so a longer body is a
	// malformed entry, not a target worth reading into memory.
	maxSymlinkTarget = 4096

	// maxLinkResolution bounds the chain isValidLinkTarget will walk, the way
	// ELOOP bounds the kernel's own resolution.
	maxLinkResolution = 64

	// symlinkAttempts bounds createSymlink's retry, so a path that another
	// extraction keeps refilling ends the entry instead of spinning on it.
	symlinkAttempts = 3
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

// extractedLink is a link entry held back until the regular ones are out.
type extractedLink struct {
	file *zip.File
	path string
}

// CreateZip creates a zip archive at destPath containing the specified paths.
// If recursive is true and a path is a directory, its contents are included
// recursively. A directory holding nothing gets an entry of its own, since it
// has no contents to carry it across.
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
				relPath, err := filepath.Rel(root, fpath)
				if err != nil {
					return err
				}
				name := filepath.Join(base, relPath)
				if fi.IsDir() {
					if name == "." {
						// Base of "/" left nothing to name the walk root with.
						return nil
					}
					// Every other directory arrives with the entries below it,
					// so only one holding nothing needs an entry of its own. It
					// is still not content, and must not make an archive that
					// holds only directories look like a finished one.
					empty, err := isEmptyDir(fpath)
					if err != nil {
						note(fpath, err)
						return nil
					}
					if !empty {
						return nil
					}
					return addDirToZip(w, name, fi)
				}
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
	// Permissions and the type flags only: setuid, setgid and sticky mean
	// nothing in a download and Unzip would hand them to os.OpenFile.
	hdr.SetMode(fi.Mode().Perm() | fi.Mode()&(os.ModeSymlink|os.ModeDir))

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

// addDirToZip writes a directory entry. The trailing slash is what every other
// zip reader keys off; the mode bit alone is not enough.
func addDirToZip(w *zip.Writer, archiveName string, fi os.FileInfo) error {
	_, err := newZipEntry(w, archiveName+"/", fi, zip.Store)
	return err
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

func isEmptyDir(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	// One entry answers the question; os.ReadDir would read and sort them all.
	if _, err := f.Readdirnames(1); err != nil {
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// Unzip extracts a zip archive to the specified destination directory.
// It validates that extracted paths stay within the destination (zip slip protection).
func Unzip(src, destDir string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer func() { _ = r.Close() }()
	return UnzipReader(&r.Reader, destDir)
}

// UnzipReader extracts an already-opened zip into destDir. Caller owns r.
// Used when the caller has pre-validated the same handle to close TOCTOU windows.
//
// A link entry—the target path as the body with ModeSymlink set, the layout
// CreateZip writes—comes back as a real symlink, dropped on a Windows host that
// makes none rather than failing the whole extraction.
//
// Nothing may leave destDir: an escaping entry name, a link target that lands
// outside once every link on the way to it is followed, and an entry written
// through a link are each refused.
func UnzipReader(r *zip.Reader, destDir string) error {
	// destDir used to appear on its own with the first entry, back when every
	// entry called os.MkdirAll on its own parent.
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Unresolved, every extraction under /tmp on darwin reads as an escape,
	// since /tmp is itself a link.
	root, err := filepath.EvalSymlinks(destDir)
	if err != nil {
		return fmt.Errorf("failed to resolve destination directory: %w", err)
	}

	var links []extractedLink
	for _, f := range r.File {
		fpath := filepath.Join(root, f.Name)
		if !isInside(root, fpath) {
			return fmt.Errorf("illegal file path in zip: %q", f.Name)
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

		// Links go last: on Windows os.Symlink picks a file or a directory link
		// by what the target is at creation time, and entry order does not
		// promise the target has been extracted yet.
		if f.Mode()&os.ModeSymlink != 0 {
			links = append(links, extractedLink{file: f, path: fpath})
			continue
		}

		if err := extractFile(f, fpath); err != nil {
			return fmt.Errorf("failed to extract %q: %w", f.Name, err)
		}
	}

	for _, link := range links {
		if err := extractSymlink(link.file, root, link.path); err != nil {
			return err
		}
	}

	return recheckLinks(root, links)
}

// recheckLinks walks every link the extraction wrote once the archive is fully
// on disk. A target is checked against what exists when the link is written, so
// a link the archive lists later can still turn an earlier one into an escape.
func recheckLinks(root string, links []extractedLink) error {
	for _, link := range links {
		target, err := os.Readlink(link.path)
		if err != nil {
			// Dropped on a host that makes no links, so there is none to check.
			continue
		}
		if isValidLinkTarget(root, link.path, filepath.ToSlash(target)) {
			continue
		}
		if err := os.Remove(link.path); err != nil {
			return err
		}
		return fmt.Errorf("illegal link target in zip: %q -> %q", link.file.Name, target)
	}

	return nil
}

func isInside(root, path string) bool {
	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// mkdirAllInside walks dir one component at a time because os.MkdirAll follows a
// symlink, which would put the entries below one outside root.
func mkdirAllInside(root, dir, name string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return fmt.Errorf("illegal file path in zip: %q", name)
	}
	if rel == "." {
		return nil
	}

	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		fi, err := os.Lstat(current)
		if os.IsNotExist(err) {
			// Commands run on a worker pool, so another extraction may win
			// the create. Not a failure, but the check below still needs
			// to see what landed.
			if err := os.Mkdir(current, 0755); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to create directory for %q: %w", name, err)
			}
			fi, err = os.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", name, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("illegal link target in zip: %q is written through a symlink", name)
		}
	}

	return nil
}

// extractSymlink is the mirror of addSymlinkToZip.
func extractSymlink(f *zip.File, root, fpath string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("failed to restore link %q: %w", f.Name, err)
	}
	body, err := io.ReadAll(io.LimitReader(rc, maxSymlinkTarget+1))
	_ = rc.Close()
	if err != nil {
		return fmt.Errorf("failed to restore link %q: %w", f.Name, err)
	}
	if len(body) > maxSymlinkTarget {
		return fmt.Errorf("illegal link target in zip: %q exceeds %d bytes", f.Name, maxSymlinkTarget)
	}

	target := string(body)
	if !isValidLinkTarget(root, fpath, target) {
		return fmt.Errorf("illegal link target in zip: %q -> %q", f.Name, target)
	}

	if err := createSymlink(target, fpath); err != nil {
		return fmt.Errorf("failed to restore link %q: %w", f.Name, err)
	}
	return nil
}

// createSymlink puts a link to target at fpath, over whatever is already there.
// A regular entry gets that from O_TRUNC in one call, and this is the same
// thing in two: commands run on a worker pool, so a second extraction can fill
// the path back in between them, and losing that race is not a failure.
func createSymlink(target, fpath string) error {
	for attempt := 0; ; attempt++ {
		if err := os.Remove(fpath); err != nil && !os.IsNotExist(err) {
			return err
		}

		err := os.Symlink(target, fpath)
		if err == nil || symlinkUnsupported(err) {
			return nil
		}
		if !os.IsExist(err) || attempt == symlinkAttempts-1 {
			return err
		}

		// Whoever won carries the same entry when the target matches, so
		// there is nothing left to write.
		if got, rerr := os.Readlink(fpath); rerr == nil && got == target {
			return nil
		}
	}
}

// isValidLinkTarget reports whether a link at fpath may carry target. It walks
// the target component by component, following every link already on disk,
// because filepath.Join folds "a/link/.." down to "a" while the kernel follows
// the link first and lands somewhere else entirely. It starts from
// filepath.Dir(fpath), which mkdirAllInside has already shown to be link-free.
func isValidLinkTarget(root, fpath, target string) bool {
	if target == "" || isAbsTarget(target) {
		return false
	}

	current := filepath.Dir(fpath)
	parts := strings.Split(target, "/")
	for steps := 0; len(parts) > 0; steps++ {
		if steps > maxLinkResolution {
			return false
		}

		part := parts[0]
		parts = parts[1:]

		switch part {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current)
		default:
			next := filepath.Join(current, part)
			if fi, err := os.Lstat(next); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(next)
				// An absolute link is refused rather than followed: only a link
				// the extraction did not write can be one, and reasoning about
				// where it lands is not worth the archive.
				if err != nil || isAbsTarget(link) {
					return false
				}
				parts = append(strings.Split(filepath.ToSlash(link), "/"), parts...)
				continue
			}
			current = next
		}

		if !isInside(root, current) {
			return false
		}
	}

	return true
}

// isAbsTarget reports whether a link target is absolute. Zip entries carry
// slash-separated paths whatever wrote them, so a leading slash counts even
// where filepath.IsAbs alone would miss it.
func isAbsTarget(target string) bool {
	return strings.HasPrefix(filepath.ToSlash(target), "/") || filepath.IsAbs(target)
}

// extractFile is the mirror of addFileToZip.
func extractFile(f *zip.File, fpath string) error {
	// os.OpenFile would write through a link sitting at the path, the one
	// component mkdirAllInside does not cover.
	if fi, err := os.Lstat(fpath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(fpath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Perm only: extraction runs as root on a normal install, so setuid, setgid
	// or sticky off an entry would land on a root-owned file. newZipEntry drops
	// the same bits on the way in.
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
