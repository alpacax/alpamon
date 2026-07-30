package runner

import (
	"testing"
	"time"
)

// The channel must come from newCompletionChannel, not from the test: a channel
// the test allocates itself would keep passing after the production capacity is
// dropped, pinning nothing.
func TestNewCompletionChannel_SurvivesSignalBeforeReceive(t *testing.T) {
	am := newTestAuthManager()
	ch := am.newCompletionChannel("req-1")

	// The websocket read loop can process the response while the waiter is still
	// inside sendSudoRequestWithRetry, before it reaches its select.
	am.signalCompletion("req-1")

	select {
	case <-ch:
	default:
		t.Fatal("completion signal was dropped before the waiter received it")
	}
}

// signalCompletion runs on the websocket read loop, so it must never wait for a
// receiver, not even when the buffer already holds a signal.
func TestSignalCompletion_DoesNotBlockWhenAlreadySignaled(t *testing.T) {
	am := newTestAuthManager()
	am.newCompletionChannel("req-1")
	am.signalCompletion("req-1")

	returned := make(chan struct{})
	go func() {
		am.signalCompletion("req-1")
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("signalCompletion blocked on a full buffer")
	}
}

// The timeout path removes the channel, so a response arriving afterwards reaches
// signalCompletion with nothing registered.
func TestSignalCompletion_UnknownRequestIsNoop(t *testing.T) {
	am := newTestAuthManager()
	am.newCompletionChannel("req-1")
	am.removeCompletionChannel("req-1")

	am.signalCompletion("req-1")
}
