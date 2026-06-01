//go:build windows

package executor

import "testing"

// TestPutEnv_CaseInsensitiveDedup verifies that setting a key removes any
// existing key that differs only in case, so cmd.Env cannot end up with
// duplicate (e.g. "Path" and "PATH") entries whose precedence is undefined.
func TestPutEnv_CaseInsensitiveDedup(t *testing.T) {
	env := map[string]string{"Path": `C:\Windows`}

	putEnv(env, "PATH", `C:\synth`)

	if _, ok := env["Path"]; ok {
		t.Error("expected old-cased key \"Path\" to be removed")
	}
	if env["PATH"] != `C:\synth` {
		t.Errorf("expected PATH=C:\\synth, got %q", env["PATH"])
	}
	if len(env) != 1 {
		t.Errorf("expected a single PATH key, got %d keys: %v", len(env), env)
	}
}
