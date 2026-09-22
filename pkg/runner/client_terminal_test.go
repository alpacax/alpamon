package runner

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTerminalTestClient() *WebsocketClient {
	return &WebsocketClient{
		RestartChan:  make(chan struct{}),
		ShutDownChan: make(chan struct{}),
	}
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestWebsocketClientShutDown_IsSafeToCallTwice(t *testing.T) {
	wc := newTerminalTestClient()

	require.NotPanics(t, func() {
		wc.ShutDown()
		wc.ShutDown()
	})

	assert.True(t, isClosed(wc.ShutDownChan), "ShutDown() did not close the shutdown channel")
}

func TestWebsocketClientRestart_IsSafeToCallTwice(t *testing.T) {
	wc := newTerminalTestClient()

	require.NotPanics(t, func() {
		wc.Restart()
		wc.Restart()
	})

	assert.True(t, isClosed(wc.RestartChan), "Restart() did not close the restart channel")
}

func TestWebsocketClientTerminalSignal_ClosesOnlyOneChannel(t *testing.T) {
	// root.go waits on both channels in one select, so closing both would leave
	// the choice between quitting and restarting to the scheduler.
	wc := newTerminalTestClient()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); wc.ShutDown() }()
	go func() { defer wg.Done(); wc.Restart() }()
	wg.Wait()

	closed := 0
	if isClosed(wc.ShutDownChan) {
		closed++
	}
	if isClosed(wc.RestartChan) {
		closed++
	}
	assert.Equal(t, 1, closed, "a concurrent shutdown and restart closed both channels")
}
