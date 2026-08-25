package utils

import (
	"fmt"
	"io"
	"os"
)

// The extract worker exists for the same reason as the archive worker:
// allow_unzip extraction ran in-process, so alpamon created every extracted
// file and directory as root. Running it as the requesting user gives those
// files the right owner and stops the extraction from writing over paths the
// user could not have touched.
//
// The archive arrives as the descriptor the parent already opened and
// validated, so the worker never resolves the path and the file that was
// checked is the file that gets extracted.

// RunExtractWorker extracts the zip on src into destDir, writing any failure
// to status, and returns the process exit code.
func RunExtractWorker(src *os.File, destDir string, status io.Writer) int {
	if err := UnzipFile(src, destDir); err != nil {
		_, _ = fmt.Fprintln(status, err.Error())
		return 1
	}
	return 0
}
