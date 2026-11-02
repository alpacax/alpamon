//go:build !windows

package executor

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, "", nil, nil,
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
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, "", nil, nil,
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
		"", "", map[string]string{"HOME": "/should/not/appear"}, 30*time.Second, "", nil, nil,
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
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, "", nil,
		func(_ context.Context, content string) { streamed.WriteString(content) },
	)

	require.NoError(t, err)
	assert.Equal(t, "STREAMED\n", output)
	assert.Equal(t, "STREAMED\n", streamed.String())
}

func TestExecFileWithStreamingHook_PropagatesExitCode(t *testing.T) {
	e := NewExecutor()
	file := openScript(t, filepath.Join(t.TempDir(), "deploy.sh"), "exit 42\n")

	exitCode, _, _ := e.ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), "", "", nil, 30*time.Second, "", nil, nil,
	)

	assert.Equal(t, 42, exitCode)
}

// runVerifiedPwd runs a verified `pwd` as username with HOME set to home and
// returns its exit code and output.
func runVerifiedPwd(t *testing.T, username, groupname, home string) (int, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pwd.sh")
	file := openScript(t, path, "pwd\n")
	require.NoError(t, os.Chmod(path, 0o644)) // Linux reopens /proc/self/fd/3 by inode mode, as the lane's memfd allows
	exitCode, output, _ := NewExecutor().ExecFileWithStreamingHook(
		context.Background(), file, verifiedFileArgv(t, "/bin/sh"), username, groupname, map[string]string{"HOME": home}, 30*time.Second, "", nil, nil,
	)
	return exitCode, output
}

func TestExecFile_StartsInHomeWhenItExists(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	exitCode, output := runVerifiedPwd(t, "root", "", home)

	assert.Equal(t, 0, exitCode, output)
	assert.Equal(t, home+"\n", output)
}

func TestExecFile_StartsInRootDirectoryWhenHomeIsMissing(t *testing.T) {
	exitCode, output := runVerifiedPwd(t, "root", "", filepath.Join(t.TempDir(), "missing"))

	assert.Equal(t, 0, exitCode, output)
	assert.Equal(t, "/\n", output)
}

func TestExecFile_StartsInRootDirectoryWhenHomeIsARegularFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.WriteFile(home, nil, 0o600))

	exitCode, output := runVerifiedPwd(t, "root", "", home)

	assert.Equal(t, 0, exitCode, output)
	assert.Equal(t, "/\n", output)
}

// The fallback belongs to the verified file lane; a shell command keeps failing
// on a missing home as it always has.
func TestExecute_ShellCommandDoesNotFallBackWhenHomeIsMissing(t *testing.T) {
	exitCode, _, err := NewExecutor().Execute(context.Background(), CommandOptions{
		Args:     []string{"/bin/sh", "-c", "pwd"},
		Username: "root",
		Env:      map[string]string{"HOME": filepath.Join(t.TempDir(), "missing")},
	})

	require.Error(t, err)
	assert.NotEqual(t, 0, exitCode)
}

func TestSearchable_FollowsOwnerGroupAndOtherBits(t *testing.T) {
	me := os.Getuid()
	stranger := uint32(me + 12345)
	const dirGroup = ^uint32(0) // stands for the directory's own group
	tests := []struct {
		name string
		mode os.FileMode
		cred syscall.Credential
		want bool
	}{
		{"owner with search", 0o700, syscall.Credential{Uid: uint32(me), Gid: stranger}, true},
		{"stranger without search", 0o700, syscall.Credential{Uid: stranger, Gid: stranger}, false},
		{"stranger with other search", 0o701, syscall.Credential{Uid: stranger, Gid: stranger}, true},
		{"stranger in the group", 0o710, syscall.Credential{Uid: stranger, Gid: stranger, Groups: []uint32{dirGroup}}, true},
		{"stranger outside the group", 0o710, syscall.Credential{Uid: stranger, Gid: stranger}, false},
		{"owner without search though others have it", 0o601, syscall.Credential{Uid: uint32(me), Gid: stranger}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "home")
			require.NoError(t, os.Mkdir(dir, 0o700))
			require.NoError(t, os.Chmod(dir, tt.mode))
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

			info, err := os.Stat(dir)
			require.NoError(t, err)
			cred := tt.cred
			if slices.Contains(cred.Groups, dirGroup) {
				cred.Groups = []uint32{info.Sys().(*syscall.Stat_t).Gid} // macOS gives a new directory its parent's group
			}

			assert.Equal(t, tt.want, searchable(info, &cred))
		})
	}
}

func TestDirSearchableBy_RefusesAHomeBehindAnUnsearchableParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	home := filepath.Join(parent, "home")
	require.NoError(t, os.MkdirAll(home, 0o755))
	require.NoError(t, os.Chmod(parent, 0o700))
	stranger := uint32(os.Getuid() + 12345)

	assert.False(t, dirSearchableBy(home, &syscall.Credential{Uid: stranger, Gid: stranger}))
}

func TestExecFile_StartsInRootDirectoryWhenTheAccountCannotEnterItsHomeWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("running as another account needs root")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account: %v", err)
	}
	group, err := user.LookupGroupId(nobody.Gid)
	require.NoError(t, err)
	home := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.Mkdir(home, 0o700))

	exitCode, output := runVerifiedPwd(t, nobody.Username, group.Name, home)

	assert.Equal(t, 0, exitCode, output)
	assert.Equal(t, "/\n", output)
}
