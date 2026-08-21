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
	// FileExecUnsupportedCode marks a platform that cannot execute a file
	// command without leaving the requester a way to change what runs.
	FileExecUnsupportedCode = "FILE_EXEC_UNSUPPORTED"
	// FileTooLargeCode marks an entrypoint past the size the agent will copy.
	FileTooLargeCode = "FILE_TOO_LARGE"
)

// maxVerifiedFileSize bounds the entrypoint the agent is willing to copy.
//
// alpacon-server caps submitted content at 64 KiB, but the agent must not
// trust a bound it cannot see: it reads from disk, where the file is whatever
// the requester last made it, and it now holds those bytes in memory. 1 MiB is
// sixteen times the server's cap, so no legitimate script comes near it, while
// keeping a single command's copy small enough that a burst of them cannot
// exhaust the agent.
const maxVerifiedFileSize = 1 << 20

// errHashMismatch is the sentinel behind FileHashMismatchCode.
var errHashMismatch = errors.New("file digest does not match the approved digest")

// errFileTooLarge is the sentinel behind FileTooLargeCode.
var errFileTooLarge = errors.New("file is larger than the agent will execute")

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

// openVerifiedFile reads path once into a sealed copy the requester cannot
// reach, hashes that copy, and returns it for execution.
//
// Executing the on-disk inode is not enough, even through a descriptor opened
// before the check. The principal this lane constrains is the requester, and
// the requester owns the file it submitted: it can rewrite those very bytes in
// place, through its own handle, in the window between the digest matching and
// the interpreter reading. That needs no compromise of anything—only a retry
// until the timing lands—so "the bytes approved are the bytes run" would be
// false against exactly the party the approval binds.
//
// Copying into a sealed object removes the window. Once sealFile returns, the
// copy is immutable (Linux) or nameless (macOS), so no write the requester can
// issue reaches the bytes that run. The digest is then computed over the
// sealed copy rather than over the source, so what is hashed is literally what
// executes: by that point nothing can change it, and a source rewritten
// mid-copy yields a digest that does not match and a command that is refused.
//
// On any failure the copy is closed before returning: no descriptor carrying
// unverified bytes reaches a caller.
func openVerifiedFile(path, expectedDigest string) (*os.File, error) {
	// codeql[go/path-injection]: Intentional - the path names a file the operator
	// asked to run on their own host, sent by the trusted Alpacon console over the
	// same authenticated channel that already carries arbitrary command lines
	// (the `system` shell), so the path is not a privilege boundary here and there
	// is no root to confine it to. What bounds this lane is the digest, checked
	// below over the sealed copy before anything executes: a path the approver did
	// not clear yields a mismatch and the command is refused.
	source, err := os.Open(path) // lgtm[go/path-injection]
	if err != nil {
		return nil, err
	}
	defer func() { _ = source.Close() }()

	// Refuse anything but a regular file: a fifo or a device says nothing
	// about what a later read would produce.
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	sealed, err := newSealedFile()
	if err != nil {
		return nil, err
	}

	// Read the source exactly once, straight into the copy. Reading it a
	// second time would invite the two reads to disagree, which is the race
	// this function exists to remove. The limit runs one byte past the cap so
	// a file sitting exactly on it is still accepted.
	copied, err := io.Copy(sealed, io.LimitReader(source, maxVerifiedFileSize+1))
	if err != nil {
		_ = sealed.Close()
		return nil, err
	}
	if copied > maxVerifiedFileSize {
		_ = sealed.Close()
		return nil, fmt.Errorf("%w (over %d bytes)", errFileTooLarge, maxVerifiedFileSize)
	}

	if err := sealFile(sealed); err != nil {
		_ = sealed.Close()
		return nil, err
	}

	digest, err := digestOfSealedFile(sealed)
	if err != nil {
		_ = sealed.Close()
		return nil, err
	}
	if digest != expectedDigest {
		_ = sealed.Close()
		return nil, fmt.Errorf("%w (expected sha256:%s, read sha256:%s)", errHashMismatch, expectedDigest, digest)
	}

	// Hashing consumed the offset. Rewind so the child reads from the start:
	// on macOS its /dev/fd/N shares this offset, and on Linux nothing should
	// depend on where the agent happened to leave it.
	if _, err := sealed.Seek(0, io.SeekStart); err != nil {
		_ = sealed.Close()
		return nil, err
	}

	return sealed, nil
}

// digestOfSealedFile hashes the sealed copy from the start. It runs after
// sealFile so the bytes it reads are already immutable, which is what lets the
// digest speak for the bytes that will run rather than for a snapshot of them.
func digestOfSealedFile(sealed *os.File) (string, error) {
	if _, err := sealed.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	digest := sha256.New()
	if _, err := io.Copy(digest, sealed); err != nil {
		return "", err
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

// prepareFileCommand turns a "file" shell command into execution arguments,
// or refuses.
//
// Verification runs here on every execution. A server-side approval is not a
// substitute: the control plane never sees the file, so only the agent can
// tell what is actually on disk at the moment of execution. A non-nil refusal
// means nothing may be executed.
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
		switch {
		case errors.Is(err, errHashMismatch):
			code = FileHashMismatchCode
		case errors.Is(err, errFileTooLarge):
			code = FileTooLargeCode
		case errors.Is(err, errSealUnavailable):
			code = FileExecUnsupportedCode
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
