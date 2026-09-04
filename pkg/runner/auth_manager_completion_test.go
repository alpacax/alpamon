package runner

import (
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
)

// registerCompletionChannel mirrors what handleSudoApprovalRequest does inside
// its registration critical section.
func registerCompletionChannel(am *AuthManager, requestID string) chan struct{} {
	am.mu.Lock()
	defer am.mu.Unlock()

	return am.newCompletionChannelLocked(requestID)
}

// TestNewCompletionChannel_SurvivesSignalBeforeReceive takes its channel from
// newCompletionChannelLocked: one the test allocates itself would keep passing
// after the production capacity is dropped.
func TestNewCompletionChannel_SurvivesSignalBeforeReceive(t *testing.T) {
	am := newTestAuthManager()
	ch := registerCompletionChannel(am, "req-1")

	// The websocket read loop can process the response while the waiter is still
	// inside sendSudoRequestWithRetry, before it reaches its select.
	am.signalCompletion("req-1")

	select {
	case <-ch:
	default:
		t.Fatal("completion signal was dropped before the waiter received it")
	}
}

// TestSignalCompletion_DoesNotBlockWhenAlreadySignaled pins that signalCompletion,
// which runs on the websocket read loop, never waits for a receiver—not even when
// the buffer already holds a signal.
func TestSignalCompletion_DoesNotBlockWhenAlreadySignaled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		am := newTestAuthManager()
		ch := registerCompletionChannel(am, "req-1")
		am.signalCompletion("req-1")

		returned := make(chan struct{})
		go func() {
			am.signalCompletion("req-1")
			close(returned)
		}()

		// Draining releases a send that did block, so a regression fails on the assertion below instead of as a bubble deadlock.
		defer func() { <-ch }()

		// Wait returns once every goroutine in the bubble is blocked, so a send still waiting for a receiver is visible here.
		synctest.Wait()
		select {
		case <-returned:
		default:
			assert.Fail(t, "signalCompletion blocked on a full buffer")
		}
	})
}

// TestSignalCompletion_UnknownRequestIsNoop covers a response arriving after the
// timeout path removed the channel.
func TestSignalCompletion_UnknownRequestIsNoop(t *testing.T) {
	am := newTestAuthManager()
	registerCompletionChannel(am, "req-1")
	am.removeCompletionChannel("req-1")

	am.signalCompletion("req-1")
}
