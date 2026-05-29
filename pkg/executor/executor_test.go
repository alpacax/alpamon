package executor

import (
	"context"
	"os/user"
	"strings"
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

// TestExecutor_DoesNotInheritProcessEnv verifies that a command run without an
// explicit environment does not inherit Alpamon's own process environment, and
// that identity variables are populated instead.
func TestExecutor_DoesNotInheritProcessEnv(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	// A variable present in Alpamon's process environment must not leak into
	// the child when no explicit env is provided.
	t.Setenv("ALPAMON_LEAK_CANARY", "leaked")

	exitCode, output, err := e.Execute(ctx, CommandOptions{
		Args:    []string{"env"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if strings.Contains(output, "ALPAMON_LEAK_CANARY") {
		t.Errorf("process environment leaked into child:\n%s", output)
	}
	if !strings.Contains(output, "HOME=") {
		t.Errorf("expected HOME to be set in child env, got:\n%s", output)
	}
	if !strings.Contains(output, "USER=") {
		t.Errorf("expected USER to be set in child env, got:\n%s", output)
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
