package utils

import (
	"encoding/json"
	"fmt"
	"io"
)

// The archive worker exists because CreateZip walks and opens the requested
// paths in-process. alpamon runs as root, so doing that in the agent applies
// root's credentials to every open and the requesting user's filesystem
// permissions never enter into it. Running the same work in a child process
// carrying the user's credentials puts the decision back with the kernel,
// which is the only place ACLs, SELinux and the rest are honored.
//
// The request arrives on stdin rather than in argv: a bulk download can list
// enough paths to overrun ARG_MAX, and argv would also have to survive
// quoting. The zip goes to stdout, which the parent points at a descriptor it
// opened itself, so the worker never resolves the destination path and cannot
// be steered at another file.

// ArchiveRequest is the worker's stdin message.
type ArchiveRequest struct {
	Paths     []string `json:"paths"`
	Recursive bool     `json:"recursive"`
}

// ArchiveSkipped is one SkippedEntry flattened for the wire, since an error
// value does not survive JSON.
type ArchiveSkipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ArchiveResponse is the worker's stderr message. It is written whether or not
// the archive succeeded, so the parent always has the skipped list to report.
type ArchiveResponse struct {
	Skipped      []ArchiveSkipped `json:"skipped,omitempty"`
	SkippedTotal int              `json:"skipped_total,omitempty"`
	Error        string           `json:"error,omitempty"`
}

// The status rides a capped buffer that silently drops the overflow, so a
// sample that outgrows it truncates into JSON the parent cannot read and a
// download whose archive is complete fails. Bounding the entry count alone is
// not enough: a tree of deeply nested paths overruns the buffer with far fewer
// than archiveSkippedReported entries. The sample is therefore bounded twice,
// by count and by serialized size, and individual paths are shortened.
//
// The summary names three paths, so a small sample plus SkippedTotal is all
// the parent needs; both bounds are far above that.
const (
	// archiveSkippedReported bounds how many skipped paths the worker names.
	archiveSkippedReported = 32
	// archiveSkippedBudget bounds what those paths may occupy, well under the
	// buffer that carries them.
	archiveSkippedBudget = 4 << 10
	// archiveSkippedPathMax shortens one path. The tail is kept because the
	// leaf names what was skipped; the elision marks that a head was dropped.
	archiveSkippedPathMax = 200
)

// shortenSkippedPath keeps a path within archiveSkippedPathMax, preserving the
// tail so the reported name still identifies what could not be archived.
func shortenSkippedPath(path string) string {
	if len(path) <= archiveSkippedPathMax {
		return path
	}
	return "..." + path[len(path)-archiveSkippedPathMax:]
}

// RunArchiveWorker reads an ArchiveRequest from in, writes the archive to dst
// and an ArchiveResponse to status, and returns the process exit code.
func RunArchiveWorker(in io.Reader, dst io.Writer, status io.Writer) int {
	var resp ArchiveResponse

	var req ArchiveRequest
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		resp.Error = fmt.Sprintf("failed to read archive request: %v", err)
	} else {
		skipped, err := WriteZip(dst, req.Paths, req.Recursive)
		resp.SkippedTotal = len(skipped)
		if len(skipped) > archiveSkippedReported {
			skipped = skipped[:archiveSkippedReported]
		}
		spent := 0
		for _, entry := range skipped {
			reported := ArchiveSkipped{
				Path:   shortenSkippedPath(entry.Path),
				Reason: entry.Reason.Error(),
			}
			spent += len(reported.Path) + len(reported.Reason)
			if spent > archiveSkippedBudget {
				break
			}
			resp.Skipped = append(resp.Skipped, reported)
		}
		if err != nil {
			resp.Error = err.Error()
		}
	}

	// A response the parent cannot parse is still better than none: it falls
	// back to the raw stream, so an encode failure must not change the exit code.
	_ = json.NewEncoder(status).Encode(resp)

	if resp.Error != "" {
		return 1
	}
	return 0
}
