package runner

import (
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSudoRequest_SurvivesSignalBeforeReceive takes its channel from
// newSudoRequest: one the test allocates itself would keep passing after the
// production capacity is dropped.
func TestNewSudoRequest_SurvivesSignalBeforeReceive(t *testing.T) {
	am := newTestAuthManager()
	req := newSudoRequest(nil, SudoApprovalRequest{RequestID: "req-1"})

	// The websocket read loop can process the response while the waiter is still
	// inside sendSudoRequestWithRetry, before it reaches its select.
	am.signalCompletion(req)

	select {
	case <-req.done:
	default:
		require.Fail(t, "completion signal was dropped before the waiter received it")
	}
}

// TestSignalCompletion_DoesNotBlockWhenAlreadySignaled pins that signalCompletion,
// which runs on the websocket read loop, never waits for a receiver—not even when
// the buffer already holds a signal.
func TestSignalCompletion_DoesNotBlockWhenAlreadySignaled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		am := newTestAuthManager()
		req := newSudoRequest(nil, SudoApprovalRequest{RequestID: "req-1"})
		am.signalCompletion(req)

		returned := make(chan struct{})
		go func() {
			am.signalCompletion(req)
			close(returned)
		}()

		// Draining releases a send that did block, so a regression fails on the assertion below instead of as a bubble deadlock.
		defer func() { <-req.done }()

		// Wait returns once every goroutine in the bubble is blocked, so a send still waiting for a receiver is visible here.
		synctest.Wait()
		select {
		case <-returned:
		default:
			assert.Fail(t, "signalCompletion blocked on a full buffer")
		}
	})
}

// TestSignalCompletion_WithoutChannelIsNoop covers a request built without
// newSudoRequest: signaling it must not block.
func TestSignalCompletion_WithoutChannelIsNoop(t *testing.T) {
	am := newTestAuthManager()
	am.signalCompletion(&SudoRequest{})
}

// TestSignalCompletion_ReachesOnlyItsInstance covers a request id (the sudo pid)
// reused while the previous waiter is still on its way out: signaling the older
// instance must not release the newer waiter.
func TestSignalCompletion_ReachesOnlyItsInstance(t *testing.T) {
	am := newTestAuthManager()
	older := newSudoRequest(nil, SudoApprovalRequest{RequestID: "req-1"})
	newer := newSudoRequest(nil, SudoApprovalRequest{RequestID: "req-1"})

	am.signalCompletion(older)

	assert.Len(t, older.done, 1, "the older instance was not signaled")
	assert.Empty(t, newer.done, "the older instance's signal reached the newer waiter")
}
