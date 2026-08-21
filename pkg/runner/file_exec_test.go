package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// digestOf renders content's sha256 in the "sha256:<hex>" wire shape.
func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeScript writes content into a temp dir and returns its path.
func writeScript(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deploy.sh")
	require.NoError(t, os.WriteFile(path, content, 0o700))
	return path
}

// skipIfNoVerifiedFileExec skips a test on platforms with no path form that
// reopens an inherited descriptor.
func skipIfNoVerifiedFileExec(t *testing.T) {
	t.Helper()
	if _, err := common.VerifiedFilePath(); err != nil {
		t.Skipf("verified file execution is unsupported here: %v", err)
	}
}

// fileCommand builds a "file" shell command carrying the structured payload.
func fileCommand(t *testing.T, id, path, interpreter string, args []string, digest string) protocol.Command {
	t.Helper()
	data, err := json.Marshal(protocol.FileExecPayload{
		Path:        path,
		Interpreter: interpreter,
		Args:        args,
		SHA256:      digest,
	})
	require.NoError(t, err)
	return protocol.Command{
		ID:    id,
		Shell: "file",
		// Deliberately at odds with the payload: nothing may be derived from it.
		Line: "/bin/echo this line is decoration",
		User: "root",
		Data: string(data),
	}
}

// dispatchCall records one dispatcher invocation.
type dispatchCall struct {
	command string
	args    *common.CommandArgs
}

// fakeDispatcher stands in for the executor so tests can assert whether a
// command reached execution at all.
type fakeDispatcher struct {
	calls []dispatchCall
}

func (d *fakeDispatcher) Execute(_ context.Context, command string, args *common.CommandArgs) (int, string, error) {
	d.calls = append(d.calls, dispatchCall{command: command, args: args})
	return 0, "ok", nil
}

func (d *fakeDispatcher) HasHandler(string) bool { return true }

func TestOpenVerifiedFile_DigestMatchReturnsRewoundDescriptor(t *testing.T) {
	content := []byte("#!/bin/sh\necho original\n")
	path := writeScript(t, content)

	file, err := openVerifiedFile(path, hexDigest(content))
	require.NoError(t, err)
	require.NotNil(t, file)
	t.Cleanup(func() { _ = file.Close() })

	// Hashing consumed the offset; the descriptor handed to the child must
	// start at the beginning of the file.
	read, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, content, read)
}

func TestOpenVerifiedFile_DigestMismatchRefuses(t *testing.T) {
	path := writeScript(t, []byte("#!/bin/sh\necho original\n"))

	file, err := openVerifiedFile(path, hexDigest([]byte("something else")))

	require.Error(t, err)
	assert.Nil(t, file, "no descriptor may escape a failed verification")
	assert.ErrorIs(t, err, errHashMismatch)
}

func TestOpenVerifiedFile_MissingFileIsNotAMismatch(t *testing.T) {
	content := []byte("#!/bin/sh\n")

	file, err := openVerifiedFile(filepath.Join(t.TempDir(), "absent.sh"), hexDigest(content))

	require.Error(t, err)
	assert.Nil(t, file)
	assert.NotErrorIs(t, err, errHashMismatch)
}

func TestOpenVerifiedFile_NonRegularFileRefused(t *testing.T) {
	dir := t.TempDir()

	file, err := openVerifiedFile(dir, hexDigest(nil))

	require.Error(t, err)
	assert.Nil(t, file)
}

// TestOpenVerifiedFile_SwapAfterVerifyKeepsOriginalBytes is the fd invariant.
// A path-based implementation—hash the path, then reopen it to execute—passes
// every other test here and fails this one.
//
// It is scoped to the platforms that run file commands: replacing a file that
// is still open is POSIX behavior, and where the handler declines there is no
// invariant to prove.
func TestOpenVerifiedFile_SwapAfterVerifyKeepsOriginalBytes(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.sh")
	original := []byte("#!/bin/sh\necho original\n")
	require.NoError(t, os.WriteFile(path, original, 0o700))

	file, err := openVerifiedFile(path, hexDigest(original))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	// Swap the file behind the path, as an attacker would between the check
	// and the use. Rename is atomic, so there is no moment a path-based
	// implementation could notice.
	swapped := []byte("#!/bin/sh\necho swapped\n")
	decoy := filepath.Join(dir, "decoy.sh")
	require.NoError(t, os.WriteFile(decoy, swapped, 0o700))
	require.NoError(t, os.Rename(decoy, path))

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, swapped, onDisk, "the swap must have landed or this test proves nothing")

	fromDescriptor, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, original, fromDescriptor,
		"the verified descriptor must still yield the bytes that were hashed")
}

func TestPrepareFileCommand_BuildsArgvFromPayloadOnly(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	content := []byte("#!/bin/sh\necho original\n")
	path := writeScript(t, content)
	// Arguments a shell would mangle: a space, an operator, a variable
	// reference and a glob. Each must survive as exactly one argv entry.
	scriptArgs := []string{"--fast", "a b", "; rm -rf /", "$HOME", "*"}
	cr := &CommandRunner{command: fileCommand(t, "", path, "/bin/bash", scriptArgs, digestOf(content))}

	args, refusal := cr.prepareFileCommand(context.Background())

	require.Nil(t, refusal)
	require.NotNil(t, args)
	t.Cleanup(func() { _ = args.VerifiedFile.Close() })

	fdPath, err := common.VerifiedFilePath()
	require.NoError(t, err)
	assert.Equal(t, append([]string{"/bin/bash", fdPath}, scriptArgs...), args.ExecArgs)
	assert.NotContains(t, args.ExecArgs, path, "argv must name the descriptor, never the path")
	assert.NotNil(t, args.VerifiedFile)
}

func TestPrepareFileCommand_HashMismatchRefusesWithoutDescriptor(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	path := writeScript(t, []byte("#!/bin/sh\necho original\n"))
	cr := &CommandRunner{command: fileCommand(t, "cmd-1", path, "/bin/bash", nil, digestOf([]byte("approved")))}

	args, refusal := cr.prepareFileCommand(context.Background())

	assert.Nil(t, args)
	require.NotNil(t, refusal)
	assert.Equal(t, FileHashMismatchCode, refusal.code)
	assert.Contains(t, refusal.String(), FileHashMismatchCode)
}

func TestPrepareFileCommand_RefusalCodes(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	content := []byte("#!/bin/sh\n")
	path := writeScript(t, content)

	tests := []struct {
		name string
		data string
		code string
	}{
		{
			name: "empty payload",
			data: "",
			code: FilePayloadInvalidCode,
		},
		{
			name: "malformed payload",
			data: `{"path":`,
			code: FilePayloadInvalidCode,
		},
		{
			name: "missing interpreter",
			data: `{"path":"` + path + `","sha256":"` + digestOf(content) + `"}`,
			code: FilePayloadInvalidCode,
		},
		{
			name: "unreadable path",
			data: `{"path":"/nonexistent/deploy.sh","interpreter":"/bin/bash","sha256":"` + digestOf(content) + `"}`,
			code: FileOpenFailedCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &CommandRunner{command: protocol.Command{ID: "cmd-1", Shell: "file", Data: tt.data}}

			args, refusal := cr.prepareFileCommand(context.Background())

			assert.Nil(t, args)
			require.NotNil(t, refusal)
			assert.Equal(t, tt.code, refusal.code)
		})
	}
}

func TestPrepareFileCommand_UnsupportedPlatformDeclinesCleanly(t *testing.T) {
	if _, err := common.VerifiedFilePath(); err == nil {
		t.Skip("this platform supports verified file execution")
	}

	content := []byte("#!/bin/sh\n")
	path := writeScript(t, content)
	cr := &CommandRunner{command: fileCommand(t, "cmd-1", path, "/bin/bash", nil, digestOf(content))}

	args, refusal := cr.prepareFileCommand(context.Background())

	assert.Nil(t, args)
	require.NotNil(t, refusal)
	assert.Equal(t, FileExecUnsupportedCode, refusal.code)
}

func TestCommandRunner_Run_FileDispatchesVerifiedDescriptor(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	content := []byte("#!/bin/sh\necho original\n")
	path := writeScript(t, content)
	dispatcher := &fakeDispatcher{}
	cr := NewCommandRunner(nil, nil, fileCommand(t, "", path, "/bin/bash", []string{"--fast"}, digestOf(content)), protocol.CommandData{}, dispatcher)

	require.NoError(t, cr.Run(context.Background()))

	require.Len(t, dispatcher.calls, 1)
	call := dispatcher.calls[0]
	assert.Equal(t, common.ExecFile.String(), call.command)
	assert.NotNil(t, call.args.VerifiedFile)
	assert.Equal(t, "/bin/bash", call.args.ExecArgs[0])
	assert.Equal(t, "--fast", call.args.ExecArgs[2])
}

func TestCommandRunner_Run_FileMismatchNeverDispatches(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	path := writeScript(t, []byte("#!/bin/sh\necho original\n"))
	dispatcher := &fakeDispatcher{}
	cr := NewCommandRunner(nil, nil, fileCommand(t, "", path, "/bin/bash", nil, digestOf([]byte("approved"))), protocol.CommandData{}, dispatcher)

	require.NoError(t, cr.Run(context.Background()))

	assert.Empty(t, dispatcher.calls, "a digest mismatch must never reach execution")
}

func TestCommandRunner_Run_FileMalformedPayloadNeverDispatches(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	cr := NewCommandRunner(nil, nil, protocol.Command{
		Shell: "file",
		Line:  "/bin/bash /opt/deploy.sh",
		Data:  "not json",
	}, protocol.CommandData{}, dispatcher)

	require.NoError(t, cr.Run(context.Background()))

	assert.Empty(t, dispatcher.calls)
}

// hexDigest returns the bare hex sum openVerifiedFile compares against.
func hexDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
