//go:build !windows

package runner

import (
	"os/exec"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPtyClientChannelsUseChannelCapacity(t *testing.T) {
	pc := NewPtyClient(protocol.CommandData{}, nil, nil)

	assert.Equal(t, channelCapacity, cap(pc.ptyToWs))
	assert.Equal(t, channelCapacity, cap(pc.wsToPty))
}

func BenchmarkNewPtyClient(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewPtyClient(protocol.CommandData{}, nil, nil)
	}
}

func TestPtyClientClose_RemovesPIDMappingFromInjectedAuthManager(t *testing.T) {
	prev := SwapAuthManager(nil) // The package global must play no part.
	t.Cleanup(func() { SwapAuthManager(prev) })
	am := newTestAuthManager()
	cmd := exec.Command("sleep", "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := cmd.Process.Pid
	am.AddPIDSessionMapping(pid, &SessionInfo{SessionID: "s1"})
	pc := &PtyClient{sessionID: "s1", cmd: cmd, manager: NewTerminalManager(am)}

	pc.close()

	_, ok := am.LookupPID(pid)
	assert.False(t, ok, "PID mapping survived close")
}
