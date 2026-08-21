package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// FileExecPayload is the structured instruction carried in Command.Data when
// Command.Shell is "file" (ADR 0053).
//
// It is the only thing that decides what runs. Command.Line renders the same
// intent for humans—display, audit, and the Ed25519 signing payload—and must
// never be parsed to derive the entrypoint, the interpreter, or the arguments.
type FileExecPayload struct {
	// Path is where the entrypoint is opened from. It selects the object to
	// verify; what an approval binds is the digest, not the path.
	Path string `json:"path"`

	// Interpreter runs the entrypoint. There is no shell wrapping it, so
	// composition belongs inside the script.
	Interpreter string `json:"interpreter"`

	// Args are handed to the entrypoint verbatim, one argv entry each.
	Args []string `json:"args"`

	// SHA256 is the approved digest, in the "sha256:<64 hex>" shape Alpamon
	// and the server already speak for sync hashes.
	SHA256 string `json:"sha256"`
}

// sha256DigestPattern matches the "sha256:<64 hex>" digest shape.
var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ParseFileExecPayload parses and validates Command.Data as a file execution
// instruction.
//
// Every field it needs is required and a malformed payload is refused rather
// than guessed at: a guess here would run bytes that no approval covers.
func (c *Command) ParseFileExecPayload() (*FileExecPayload, error) {
	if strings.TrimSpace(c.Data) == "" {
		return nil, errors.New("file command carries no data payload")
	}

	var payload FileExecPayload
	if err := json.Unmarshal([]byte(c.Data), &payload); err != nil {
		return nil, fmt.Errorf("file command payload is not valid JSON: %w", err)
	}

	// Hex case is not part of the digest's identity, so normalize before the
	// shape check rather than refusing an upper-case but otherwise valid one.
	payload.SHA256 = strings.ToLower(payload.SHA256)

	switch {
	case payload.Path == "":
		return nil, errors.New("file command payload has no path")
	case !isPOSIXAbsolute(payload.Path):
		return nil, fmt.Errorf("file command path is not absolute: %q", payload.Path)
	case payload.Interpreter == "":
		return nil, errors.New("file command payload has no interpreter")
	// A bare name would be resolved through PATH at exec time, and PATH is
	// influenced by the command's own environment. The digest binds the script
	// but says nothing about the program interpreting it, so a relative
	// interpreter is a way to swap what actually runs while the approved digest
	// still matches. The server validates this too; the agent does not take its
	// word for it, because the agent is where the guarantee is kept.
	case !isPOSIXAbsolute(payload.Interpreter):
		return nil, fmt.Errorf(
			"file command interpreter is not absolute: %q", payload.Interpreter,
		)
	case !sha256DigestPattern.MatchString(payload.SHA256):
		return nil, fmt.Errorf("file command payload has no valid sha256 digest: %q", payload.SHA256)
	}

	return &payload, nil
}

// ExpectedDigest returns the hex digest without the "sha256:" prefix, ready to
// compare against a computed sum.
func (p *FileExecPayload) ExpectedDigest() string {
	return strings.TrimPrefix(p.SHA256, "sha256:")
}

// isPOSIXAbsolute reports whether a wire path is absolute in POSIX terms.
//
// Deliberately not filepath.IsAbs: that is evaluated against the *building*
// OS, so a Windows build would read "/opt/deploy.sh" as relative and refuse a
// payload every other build accepts. The wire contract is a POSIX path — the
// lane declines on Windows before a payload is ever parsed — so the check has
// to mean the same thing wherever it compiles.
func isPOSIXAbsolute(p string) bool {
	return strings.HasPrefix(p, "/")
}
