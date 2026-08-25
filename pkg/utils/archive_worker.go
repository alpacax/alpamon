package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
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
// status that outgrows it becomes JSON the parent cannot read, and a download
// whose archive is complete fails. Three bounds keep it inside: the sample is
// capped by entry count and by serialized size, since a tree of deeply nested
// paths overruns the buffer with far fewer entries than the count allows, and
// the encoded form is capped as a whole, since the error field is not part of
// the sample budget.
//
// The summary names three paths, so a small sample plus SkippedTotal is all the
// parent needs; every bound here is far above that.
const (
	// archiveSkippedReported bounds how many skipped paths the worker names.
	archiveSkippedReported = 32
	// archiveSkippedBudget bounds what those paths may occupy, well under the
	// buffer that carries them.
	archiveSkippedBudget = 4 << 10
	// archiveSkippedPathMax shortens one path. The tail is kept because the
	// leaf names what was skipped; the elision marks that a head was dropped.
	archiveSkippedPathMax = 200
	// archiveStatusMax bounds the encoded status. The two bounds above budget
	// the sample only, and the error field is not part of that budget: a
	// wrapped *PathError reaches PATH_MAX on its own, so a full sample beside
	// one still overruns the buffer. This bound is enforced on the encoded
	// form, so the parent can always read a status whatever it carries.
	archiveStatusMax = 6 << 10
)

// shortenSkippedPath keeps a path within archiveSkippedPathMax, preserving the
// tail so the reported name still identifies what could not be archived.
func shortenSkippedPath(path string) string {
	if len(path) <= archiveSkippedPathMax {
		return path
	}
	tail := path[len(path)-archiveSkippedPathMax:]
	// Cutting at a byte offset lands inside a multi-byte rune for most offsets,
	// and non-ASCII names are ordinary on the machines this runs on. The broken
	// rune survives json.Marshal as U+FFFD, so the path the summary shows to
	// identify what was skipped arrives mangled. Advance to the next boundary.
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	return "..." + tail
}

// truncateHead keeps the first max bytes of s, backing off to a rune boundary
// so what survives stays readable. The head is kept because an error names its
// cause there.
func truncateHead(s string, max int) string {
	if len(s) <= max {
		return s
	}
	head := s[:max]
	for len(head) > 0 && !utf8.ValidString(head) {
		head = head[:len(head)-1]
	}
	return head + "..."
}

// encodeArchiveStatus writes resp to status within archiveStatusMax. The buffer
// carrying the status drops its overflow silently, and a status the parent
// cannot parse costs it the skipped list and the error message both, so the
// sample is dropped and the error shortened rather than letting that happen.
// SkippedTotal survives either way, so the summary can still report the count.
func encodeArchiveStatus(status io.Writer, resp ArchiveResponse) {
	encoded, err := json.Marshal(resp)
	if err != nil || len(encoded) < archiveStatusMax {
		_ = json.NewEncoder(status).Encode(resp)
		return
	}

	resp.Skipped = nil
	resp.Error = truncateHead(resp.Error, archiveStatusMax/2)
	_ = json.NewEncoder(status).Encode(resp)
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

	// An encode failure must not change the exit code: the parent falls back to
	// the raw stream, which is worse than a status but better than none.
	encodeArchiveStatus(status, resp)

	if resp.Error != "" {
		return 1
	}
	return 0
}
