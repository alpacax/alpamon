package executor

import (
	"context"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExecutor_TimeoutReturns124(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	exitCode, output, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"sleep", "10"},
		Timeout: 500 * time.Millisecond,
	})

	if exitCode != 124 {
		t.Errorf("expected exit code 124, got %d", exitCode)
	}
	if !strings.Contains(output, "Command timed out after") {
		t.Errorf("expected timeout message in output, got %q", output)
	}
	if err == nil {
		t.Error("expected non-nil error on timeout")
	}
}

func TestExecutor_NoTimeoutOnFastCommand(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	exitCode, _, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"echo", "hello"},
		Timeout: 5 * time.Second,
	})

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecutor_ExecWithStreamingHook_StreamsChunks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}

	e := NewExecutor()
	ctx := context.Background()

	var mu sync.Mutex
	var chunks []string
	callback := func(content string) {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, content)
	}

	exitCode, output, err := e.ExecWithStreamingHook(
		ctx,
		[]string{"/bin/sh", "-c", "printf 'line1\\nline2\\nline3\\n'"},
		"", "", nil, 5*time.Second, nil, callback,
	)
	if err != nil {
		t.Fatalf("ExecWithStreamingHook: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	assembled := strings.Join(chunks, "")
	if !strings.Contains(assembled, "line1") || !strings.Contains(assembled, "line3") {
		t.Errorf("unexpected chunks: %q", assembled)
	}
	if output != "" {
		t.Errorf("streaming path should not return captured output, got %q", output)
	}
}

func TestExecutor_StartFailureSurfacesErrorInResult(t *testing.T) {
	e := NewExecutor()
	missing := "/no/such/binary/should/exist/here-" + t.Name()

	exitCode, result, err := e.Execute(context.Background(), CommandOptions{
		Args:    []string{missing},
		Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if exitCode == 0 {
		t.Errorf("expected non-zero exit, got %d", exitCode)
	}
	if !strings.Contains(result, missing) && !strings.Contains(result, "no such file") {
		t.Errorf("result should carry start-failure diagnostic, got %q", result)
	}
}

func TestExecutor_StreamingTimeoutBannerHasNoLeadingNewlines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}
	e := NewExecutor()
	exitCode, result, err := e.ExecWithStreamingHook(
		context.Background(),
		[]string{"/bin/sh", "-c", "sleep 5"},
		"", "", nil, 500*time.Millisecond,
		nil, func(content string) {},
	)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if exitCode != 124 {
		t.Errorf("expected 124, got %d", exitCode)
	}
	if strings.HasPrefix(result, "\n") {
		t.Errorf("streaming timeout banner should not have leading newline: %q", result)
	}
	if !strings.HasPrefix(result, "Command timed out after") {
		t.Errorf("unexpected banner: %q", result)
	}
}

func TestExecutor_PlainExecuteWithoutCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh -c which is Unix-only")
	}

	e := NewExecutor()
	exitCode, output, err := e.Execute(context.Background(), CommandOptions{
		Args:    []string{"/bin/sh", "-c", "printf 'hello\\n'"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
	if !strings.Contains(output, "hello") {
		t.Errorf("output: got %q", output)
	}
}

// TestExecutor_BuildEnvSetsUserIdentity verifies the environment is populated
// with the resolved user's identity and the deterministic defaults.
func TestExecutor_BuildEnvSetsUserIdentity(t *testing.T) {
	e := NewExecutor()

	usr, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}

	// Empty username resolves to the current user (Alpamon is not root in tests).
	env := e.buildEnv("", nil)

	if env["HOME"] != usr.HomeDir {
		t.Errorf("expected HOME=%q, got %q", usr.HomeDir, env["HOME"])
	}
	if env["USER"] != usr.Username {
		t.Errorf("expected USER=%q, got %q", usr.Username, env["USER"])
	}
	if env["LOGNAME"] != usr.Username {
		t.Errorf("expected LOGNAME=%q, got %q", usr.Username, env["LOGNAME"])
	}
	for _, key := range []string{"PATH", "SHELL", "TERM", "LANG"} {
		if env[key] == "" {
			t.Errorf("expected default env %q to be set", key)
		}
	}
}

// TestExecutor_BuildEnvOverridePrecedence verifies caller-provided env values
// take precedence over both the defaults and the resolved user identity.
func TestExecutor_BuildEnvOverridePrecedence(t *testing.T) {
	e := NewExecutor()

	env := e.buildEnv("", map[string]string{
		"HOME": "/custom/home",
		"FOO":  "bar",
	})

	if env["HOME"] != "/custom/home" {
		t.Errorf("expected override HOME=/custom/home, got %q", env["HOME"])
	}
	if env["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", env["FOO"])
	}
}

// TestExecutor_ExpandArgsUsesBuiltEnv locks in the behavior that argument
// variable references are expanded from the synthesized environment even when
// the caller passes no env (previously such args were left untouched).
func TestExecutor_ExpandArgsUsesBuiltEnv(t *testing.T) {
	e := NewExecutor()

	env := e.buildEnv("", nil)
	args := e.expandArgs([]string{"echo", "$HOME", "${USER}"}, env)

	if args[1] != env["HOME"] {
		t.Errorf("expected $HOME expanded to %q, got %q", env["HOME"], args[1])
	}
	if args[2] != env["USER"] {
		t.Errorf("expected ${USER} expanded to %q, got %q", env["USER"], args[2])
	}
}
