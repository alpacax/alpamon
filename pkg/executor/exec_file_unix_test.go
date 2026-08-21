//go:build !windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifiedFileArgv builds the argv for a verified entrypoint: the interpreter,
// the descriptor path, then the script arguments. It mirrors what the runner
// builds after the digest check, and it never names the original path.
func verifiedFileArgv(t *testing.T, interpreter string, scriptArgs ...string) []string {
	t.Helper()
	fdPath, err := common.VerifiedFilePath()
	if err != nil {
		t.Skipf("verified file execution is unsupported here: %v", err)
	}
	return append([]string{interpreter, fdPath}, scriptArgs...)
}

// openScript writes content at path and returns an open descriptor on it,
// standing in for the descriptor the runner hands over after verification.
func openScript(t *testing.T, path string, content string) *os.File {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o700))
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestExecFileWithStreamingHook_RunsInheritedDescriptor(t *testing.T) {
	e := NewExecutor()
	file := openScript(t, filepath.Join(t.TempDir(), "deploy.sh"), "printf 'ORIGINAL\\n'\n")

	exitCode, output, err := e.ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, nil, nil,
	)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "ORIGINAL\n", output)
}

// TestExecFileWithStreamingHook_SwapAtPathRunsVerifiedBytes is the end-to-end
// form of the fd invariant: the file behind the path is replaced after the
// descriptor was opened, and the child still runs the original bytes. The
// second half of the test executes the same path directly to show that a
// path-based implementation would have run the attacker's script instead.
func TestExecFileWithStreamingHook_SwapAtPathRunsVerifiedBytes(t *testing.T) {
	e := NewExecutor()
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.sh")
	file := openScript(t, path, "printf 'ORIGINAL\\n'\n")

	// Atomically swap a different script in at the path, exactly as an
	// attacker would in the window between the digest check and the exec.
	decoy := filepath.Join(dir, "decoy.sh")
	require.NoError(t, os.WriteFile(decoy, []byte("printf 'SWAPPED\\n'\n"), 0o700))
	require.NoError(t, os.Rename(decoy, path))

	_, output, err := e.ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, nil, nil,
	)

	require.NoError(t, err)
	assert.Equal(t, "ORIGINAL\n", output, "the executed object must be the verified one")

	// Control: naming the path instead of the descriptor runs the swap.
	_, pathOutput, err := e.Exec(context.Background(), []string{"/bin/sh", path}, "", "", nil, 30*time.Second)
	require.NoError(t, err)
	require.Equal(t, "SWAPPED\n", pathOutput, "the swap must be live or this test proves nothing")
}

// TestExecFileWithStreamingHook_ArgsArePassedLiterally covers arguments a shell
// would mangle. There is no shell between the agent and the entrypoint, so each
// argument must arrive as exactly one argv entry, unsplit and unexpanded.
func TestExecFileWithStreamingHook_ArgsArePassedLiterally(t *testing.T) {
	e := NewExecutor()
	file := openScript(t, filepath.Join(t.TempDir(), "deploy.sh"),
		"for arg in \"$@\"; do printf '[%s]\\n' \"$arg\"; done\n")
	scriptArgs := []string{"--fast", "a b", "; rm -rf /", "$HOME", "*", "&& echo chained"}

	_, output, err := e.ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh", scriptArgs...),
		"", "", map[string]string{"HOME": "/should/not/appear"}, 30*time.Second, nil, nil,
	)

	require.NoError(t, err)
	want := "[" + strings.Join(scriptArgs, "]\n[") + "]\n"
	assert.Equal(t, want, output)
}

func TestExecFileWithStreamingHook_StreamsChunks(t *testing.T) {
	e := NewExecutor()
	file := openScript(t, filepath.Join(t.TempDir(), "deploy.sh"), "printf 'STREAMED\\n'\n")

	var streamed strings.Builder
	_, output, err := e.ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, nil,
		func(content string) { streamed.WriteString(content) },
	)

	require.NoError(t, err)
	assert.Equal(t, "STREAMED\n", output)
	assert.Equal(t, "STREAMED\n", streamed.String())
}

func TestExecFileWithStreamingHook_PropagatesExitCode(t *testing.T) {
	e := NewExecutor()
	file := openScript(t, filepath.Join(t.TempDir(), "deploy.sh"), "exit 42\n")

	exitCode, _, _ := e.ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, nil, nil,
	)

	assert.Equal(t, 42, exitCode)
}
