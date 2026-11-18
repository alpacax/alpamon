//go:build !windows

package runner

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPausedTerminalDropsInputWithoutBufferingIt(t *testing.T) {
	server := &fakeControlServer{}
	server.set(workSessionActive, 0)
	r := newTestRegistry(server)
	cc := &ControlClient{workSessions: r}
	release, err := r.admit(context.Background(), attribution(0), "cmd-open")
	require.NoError(t, err)

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = reader.Close() }()
	pc := &PtyClient{sessionID: "websh-1", ptmx: writer, wsToPty: make(chan []byte, channelCapacity)}
	pc.TrackCommand(withWorkSession(context.Background(), &workSessionBinding{registry: r, id: wsID}), "cmd-open")
	release()
	_, terminals := r.owned(wsID)
	require.Equal(t, []string{"cmd-open"}, terminals)

	cc.HandleMessage(pauseFrame(t, 1))
	require.NoError(t, pc.writeInput([]byte("dropped")))
	cc.HandleMessage(resumeFrame(t, 2))
	require.NoError(t, pc.writeInput([]byte("typed")))
	require.NoError(t, writer.Close())

	written, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "typed", string(written), "input sent while paused is never replayed")

	pc.releaseWorkSession()
	_, terminals = r.owned(wsID)
	assert.Empty(t, terminals)
}
