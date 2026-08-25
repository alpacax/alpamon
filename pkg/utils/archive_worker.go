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
	Skipped []ArchiveSkipped `json:"skipped,omitempty"`
	Error   string           `json:"error,omitempty"`
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
		for _, entry := range skipped {
			resp.Skipped = append(resp.Skipped, ArchiveSkipped{
				Path:   entry.Path,
				Reason: entry.Reason.Error(),
			})
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
