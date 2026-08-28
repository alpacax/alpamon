package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The extract worker exists for the same reason as the archive worker:
// allow_unzip extraction ran in-process, so alpamon created every extracted
// file and directory as root. Running it as the requesting user gives those
// files the right owner and stops the extraction from writing over paths the
// user could not have touched.
//
// The worker also opens the source and removes it afterwards, so the agent
// never resolves a path the requesting user controls. O_NOFOLLOW refuses a
// symlink at the final component, but the directories above it are still
// dereferenced by whoever opens, and the user can swap those. Doing the open
// here means such a swap resolves against the user's own credentials and buys
// nothing. The same argument covers the unlink, which traverses those
// directories too.

// RunExtractWorker extracts the archive at srcPath into destDir, writing any
// failure to status, and returns the process exit code. A source that is not a
// readable archive is not a failure: nothing is extracted, the source is left
// alone, and the download stands.
func RunExtractWorker(srcPath, destDir string, status io.Writer) int {
	src := OpenIfZip(srcPath, filepath.Ext(srcPath))
	if src == nil {
		return 0
	}

	err := UnzipFile(src, destDir)
	// Closed here rather than on a defer, because the unlink below has to come
	// after it. Go opens without FILE_SHARE_DELETE, so on Windows a remove runs
	// into a sharing violation while the handle is still open, and the error is
	// discarded, which would leave the source behind on every extraction.
	_ = src.Close()
	if err != nil {
		_, _ = fmt.Fprintln(status, err.Error())
		return 1
	}

	// The archive has been unpacked, so the copy of it is redundant. A failed
	// unlink does not undo the extraction, so it does not fail the download.
	_ = os.Remove(srcPath)
	return 0
}
