package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
)

// Refusal codes for a "file" shell command that never ran. They are a closed
// set of fixed strings so the console can tell a refusal apart from a script
// that merely exited non-zero, and so a refusal reads the same in every
// deployment.
const (
	// FileHashMismatchCode marks the digest check failing: the file behind the
	// path is not the file the approval covers. Never a reason to fall back to
	// running it.
	FileHashMismatchCode = "FILE_HASH_MISMATCH"
	// FilePayloadInvalidCode marks a malformed or incomplete instruction.
	FilePayloadInvalidCode = "FILE_PAYLOAD_INVALID"
	// FileOpenFailedCode marks an entrypoint that could not be opened, stated
	// or read—including one that is not a regular file.
	FileOpenFailedCode = "FILE_OPEN_FAILED"
	// FileExecUnsupportedCode marks a platform with no path form that reopens
	// the verified descriptor.
	FileExecUnsupportedCode = "FILE_EXEC_UNSUPPORTED"
)

// errHashMismatch is the sentinel behind FileHashMismatchCode.
var errHashMismatch = errors.New("file digest does not match the approved digest")

// fileRefusal is a file command that must be reported instead of executed.
type fileRefusal struct {
	code string
	err  error
}

// String renders the refusal for the command result, code first so the server
// can match on it without parsing the diagnostic that follows.
func (r *fileRefusal) String() string {
	return fmt.Sprintf("%s: %s", r.code, r.err)
}

// openVerifiedFile opens path once, hashes the descriptor it got back, and
// returns that same descriptor for execution.
//
// The single open is the whole guarantee. Hashing a path and then reopening it
// to execute leaves a window in which the file can be swapped between the
// check and the use, which is precisely what the digest exists to close, so
// this never touches the path again after os.Open. On mismatch it returns
// errHashMismatch with the descriptor already closed: there is no path on
// which unverified bytes reach a caller.
func openVerifiedFile(path, expectedDigest string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Refuse anything but a regular file: hashing a fifo or a device says
	// nothing about what a later read would produce.
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if actual := hex.EncodeToString(digest.Sum(nil)); actual != expectedDigest {
		_ = file.Close()
		return nil, fmt.Errorf("%w (expected sha256:%s, read sha256:%s)", errHashMismatch, expectedDigest, actual)
	}

	// Hashing consumed the offset. Rewind the same descriptor rather than
	// reopening: on macOS the child's /dev/fd/N shares this offset, and on
	// Linux nothing should depend on where the agent happened to leave it.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}

	return file, nil
}

// prepareFileCommand turns a "file" shell command into execution arguments,
// or refuses.
//
// Verification runs here on every execution. A server-side approval is not a
// substitute: the control plane never sees the file, so only the agent can
// tell whether the bytes on disk are still the approved ones. A non-nil
// refusal means nothing may be executed.
//
// On success the caller owns args.VerifiedFile and must close it.
func (cr *CommandRunner) prepareFileCommand(ctx context.Context) (*common.CommandArgs, *fileRefusal) {
	// Resolve the descriptor path first: on a platform that cannot name an
	// inherited descriptor there is no point opening anything.
	fdPath, err := common.VerifiedFilePath()
	if err != nil {
		return nil, &fileRefusal{code: FileExecUnsupportedCode, err: err}
	}

	payload, err := cr.command.ParseFileExecPayload()
	if err != nil {
		return nil, &fileRefusal{code: FilePayloadInvalidCode, err: err}
	}

	file, err := openVerifiedFile(payload.Path, payload.ExpectedDigest())
	if err != nil {
		code := FileOpenFailedCode
		if errors.Is(err, errHashMismatch) {
			code = FileHashMismatchCode
		}
		return nil, &fileRefusal{code: code, err: err}
	}

	// The argv is built from the structured payload alone. cr.command.Line is
	// a human rendering of the same intent and is never parsed to decide what
	// runs. Each payload argument becomes one argv entry, so nothing in it is
	// split, globbed, or read as an operator.
	execArgs := make([]string, 0, len(payload.Args)+2)
	execArgs = append(execArgs, payload.Interpreter, fdPath)
	execArgs = append(execArgs, payload.Args...)

	return &common.CommandArgs{
		CommandID:     cr.command.ID,
		Username:      cr.command.User,
		Groupname:     cr.command.Group,
		Env:           cr.command.Env,
		VerifiedFile:  file,
		ExecArgs:      execArgs,
		ChunkCallback: cr.newChunkCallback(ctx),
	}, nil
}
