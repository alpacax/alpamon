//go:build windows

package executor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPutEnv_CaseInsensitiveDedup verifies that setting a key removes any
// existing key that differs only in case, so cmd.Env cannot end up with
// duplicate (e.g. "Path" and "PATH") entries whose precedence is undefined.
func TestPutEnv_CaseInsensitiveDedup(t *testing.T) {
	env := map[string]string{"Path": `C:\Windows`}

	putEnv(env, "PATH", `C:\synth`)

	_, ok := env["Path"]
	assert.False(t, ok, "expected old-cased key \"Path\" to be removed")
	assert.Equal(t, `C:\synth`, env["PATH"])
	assert.Len(t, env, 1, "expected a single PATH key")
}
