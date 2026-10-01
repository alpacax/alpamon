//go:build !windows

package runner

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionID_CurrentProcess(t *testing.T) {
	sid, ok := sessionID(os.Getpid())
	require.True(t, ok, "expected a valid sid for the current process")
	require.Positive(t, sid, "expected a valid sid for the current process")
}

func TestSessionID_InvalidPID(t *testing.T) {
	// pid 0 would make getsid report the caller's (Alpamon's) own session; we
	// reject it up front so a bogus request can never match Alpamon's session.
	_, ok := sessionID(0)
	assert.False(t, ok, "expected ok=false for pid 0")
	_, ok = sessionID(-1)
	assert.False(t, ok, "expected ok=false for negative pid")
}
