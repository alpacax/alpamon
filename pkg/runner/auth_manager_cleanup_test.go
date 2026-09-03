package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerPipeRequest registers a pending request the way handleSudoApprovalRequest
// does, minus the completion channel—tests that need one add it with
// registerCompletionChannel.
func registerPipeRequest(am *AuthManager, req SudoApprovalRequest) net.Conn {
	client, server := net.Pipe()
	am.pidToSessionMap[req.PID] = &SessionInfo{
		Kind:      TrackerKindWebsh,
		SessionID: req.SessionID,
		PID:       req.PID,
		Requests: map[string]*SudoRequest{
			req.RequestID: {Connection: server, Request: req},
		},
	}
	return client
}

// expectSingleResponse decodes the one response the connection is allowed to
// carry and asserts the write was followed by a close.
func expectSingleResponse(t *testing.T, client net.Conn) SudoApprovalResponse {
	t.Helper()

	// Without this a regression hangs until the suite-wide panic instead of failing here.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))

	dec := json.NewDecoder(client)
	var resp SudoApprovalResponse
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	// EOF proves both: no second response, and the connection was closed.
	if err := dec.Decode(&resp); !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF after single response, got %v", err)
	}
	return resp
}

// TestFinalizeRequest_SendsSingleFullResponseAndCloses pins the one-response rule:
// the PAM client parses all it reads until EOF as one JSON document (alpamon-pam
// alpacon_approval.c), so a second response would break it.
func TestFinalizeRequest_SendsSingleFullResponseAndCloses(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{
		RequestID: "req-1",
		Username:  "alice",
		Groupname: "wheel",
		PID:       4242,
		PPID:      4200,
		Command:   "sudo systemctl restart nginx",
		SessionID: "sess-1",
	}
	client := registerPipeRequest(am, req)

	// net.Pipe is unbuffered, so the write has to run against this goroutine's reads.
	go am.finalizeRequest(req.RequestID, "Communication error")

	want := SudoApprovalResponse{
		RequestID: "req-1",
		Type:      "sudo_approval_response",
		Username:  "alice",
		Groupname: "wheel",
		PID:       4242,
		PPID:      4200,
		Command:   "sudo systemctl restart nginx",
		SessionID: "sess-1",
		Reason:    "Communication error",
	}
	if resp := expectSingleResponse(t, client); resp != want {
		t.Errorf("response: got %+v, want %+v", resp, want)
	}

	// finalizeRequest deregisters before it writes, so the close seen above
	// means the deletion already happened.
	if _, exists := am.pidToSessionMap[4242].Requests["req-1"]; exists {
		t.Error("request was not deregistered")
	}
}

// TestFinalizeRequest_UnknownRequestIsNoop covers a request HandleSudoApprovalResponse
// already took: finalizing it must leave every other pending request alone.
func TestFinalizeRequest_UnknownRequestIsNoop(t *testing.T) {
	am := newTestAuthManager()
	pending := SudoApprovalRequest{RequestID: "req-pending", PID: 2, SessionID: "sess-2"}
	registerPipeRequest(am, pending)

	am.finalizeRequest("req-gone", "Response timeout")

	if _, exists := am.pidToSessionMap[2].Requests["req-pending"]; !exists {
		t.Error("an unrelated pending request was dropped")
	}
}

// TestFinalizeRequest_RacesHandleResponse is the race the single-ownership rule
// exists for: a server response arriving at the same moment the request gives up.
// Both paths delete under am.mu, so only the winner finds the request and writes.
func TestFinalizeRequest_RacesHandleResponse(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{RequestID: "req-race", Username: "alice", PID: 3333, SessionID: "sess-race"}
	client := registerPipeRequest(am, req)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		am.finalizeRequest(req.RequestID, "Response timeout")
	}()
	go func() {
		defer wg.Done()
		_ = am.HandleSudoApprovalResponse(SudoApprovalResponse{
			RequestID: req.RequestID,
			Type:      "sudo_approval_response",
			Approved:  true,
			Username:  "alice",
			PID:       3333,
			SessionID: "sess-race",
		})
	}()

	resp := expectSingleResponse(t, client)
	if resp.RequestID != req.RequestID {
		t.Errorf("request_id: got %q, want %q", resp.RequestID, req.RequestID)
	}
	// Exactly one of the two wrote, so the response is wholly one path's or
	// wholly the other's—never a mix.
	approval := resp.Approved && resp.Reason == ""
	timeout := !resp.Approved && resp.Reason == "Response timeout"
	if !approval && !timeout {
		t.Errorf("response belongs to neither path: %+v", resp)
	}

	wg.Wait()
}

// TestRemovePIDSessionMapping_DeniesPendingRequestsAndSignalsWaiter checks both
// halves of the remover's job for requests it puts out of finalizeRequest's reach:
// answering and closing them, or the PAM client waits out its own timeout and falls
// back to its fail-open setting, and signalling handleSudoApprovalRequest, which is
// still parked on the completion channel holding an already-answered request.
func TestRemovePIDSessionMapping_DeniesPendingRequestsAndSignalsWaiter(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{
		RequestID: "req-websh",
		Username:  "alice",
		PID:       7777,
		Command:   "sudo reboot",
		SessionID: "sess-websh",
	}
	client := registerPipeRequest(am, req)
	completion := registerCompletionChannel(am, req.RequestID)

	go am.RemovePIDSessionMapping(7777)

	want := SudoApprovalResponse{
		RequestID: "req-websh",
		Type:      "sudo_approval_response",
		Username:  "alice",
		PID:       7777,
		Command:   "sudo reboot",
		SessionID: "sess-websh",
		Reason:    "Session ended",
	}
	if resp := expectSingleResponse(t, client); resp != want {
		t.Errorf("response: got %+v, want %+v", resp, want)
	}

	select {
	case <-completion:
	case <-time.After(2 * time.Second):
		t.Error("waiter was never signaled")
	}
}

// TestHandleSudoApprovalResponse_SignalsWaiterOnWriteFailure covers a client that
// gave up before the server answered: the write fails, but the request is already
// deregistered, so nothing else will ever release the waiter.
func TestHandleSudoApprovalResponse_SignalsWaiterOnWriteFailure(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{RequestID: "req-dead", Username: "alice", PID: 9999, SessionID: "sess-dead"}
	client := registerPipeRequest(am, req)
	completion := registerCompletionChannel(am, req.RequestID)
	_ = client.Close()

	err := am.HandleSudoApprovalResponse(SudoApprovalResponse{
		RequestID: req.RequestID,
		Type:      "sudo_approval_response",
		Approved:  true,
		Username:  "alice",
		PID:       9999,
		SessionID: "sess-dead",
	})
	if err == nil {
		t.Error("a write to a closed client should be reported")
	}

	select {
	case <-completion:
	default:
		t.Error("waiter was never signaled")
	}
}

// TestAddPIDSessionMapping_SameEntryKeepsRequests checks re-registering the entry
// already installed for a pid displaces nothing. The connection is closed up front:
// a regression that denied them would fail its write instead of blocking on net.Pipe.
func TestAddPIDSessionMapping_SameEntryKeepsRequests(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{RequestID: "req-same", Username: "alice", PID: 1212, SessionID: "sess-same"}
	client := registerPipeRequest(am, req)
	_ = client.Close()
	session := am.pidToSessionMap[1212]

	am.AddPIDSessionMapping(1212, session)

	if _, exists := session.Requests[req.RequestID]; !exists {
		t.Error("re-registering the same entry dropped its pending request")
	}
}

// TestAddPIDSessionMapping_DeniesReplacedRequests covers a pid reused by a new
// session: overwriting puts the old entry's requests out of reach just as removing
// it does, so the replacement has to answer them too.
func TestAddPIDSessionMapping_DeniesReplacedRequests(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{RequestID: "req-stale", Username: "alice", PID: 5555, SessionID: "sess-old"}
	client := registerPipeRequest(am, req)

	go am.AddPIDSessionMapping(5555, &SessionInfo{
		SessionID: "sess-new",
		PID:       5555,
		Requests:  map[string]*SudoRequest{},
	})

	want := SudoApprovalResponse{
		RequestID: "req-stale",
		Type:      "sudo_approval_response",
		Username:  "alice",
		PID:       5555,
		SessionID: "sess-old",
		Reason:    "Session replaced",
	}
	if resp := expectSingleResponse(t, client); resp != want {
		t.Errorf("response: got %+v, want %+v", resp, want)
	}
}

func TestAddPIDCommandMapping_DeniesReplacedRequests(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{RequestID: "req-stale-cmd", Username: "bob", PID: 6666}
	client := registerPipeRequest(am, req)

	go am.AddPIDCommandMapping(6666, "cmd-new", "bob")

	want := SudoApprovalResponse{
		RequestID: "req-stale-cmd",
		Type:      "sudo_approval_response",
		Username:  "bob",
		PID:       6666,
		Reason:    "Session replaced",
	}
	if resp := expectSingleResponse(t, client); resp != want {
		t.Errorf("response: got %+v, want %+v", resp, want)
	}
}

// TestHandleSudoApprovalRequest_RetryFailureAnswersOnce is issue #396 itself: the
// retry-failure path used to write its own response and close, then leave the
// still-registered request for a second response and close. The cancelled context
// fails the retry immediately instead of spending its 25s budget.
func TestHandleSudoApprovalRequest_RetryFailureAnswersOnce(t *testing.T) {
	am := newTestAuthManager()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	am.ctx = ctx
	am.pidToSessionMap[4200] = &SessionInfo{
		Kind:      TrackerKindWebsh,
		SessionID: "sess-retry",
		PID:       4200,
		Requests:  make(map[string]*SudoRequest),
	}
	data, err := json.Marshal(SudoApprovalRequest{
		RequestID: "req-retry",
		Type:      "sudo_approval",
		Username:  "alice",
		PID:       424242,
		PPID:      4200,
		Command:   "sudo reboot",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()

	go am.handleSudoApprovalRequest(data, server)

	want := SudoApprovalResponse{
		RequestID:    "req-retry",
		Type:         "sudo_approval_response",
		Username:     "alice",
		PID:          424242,
		PPID:         4200,
		Command:      "sudo reboot",
		IsAlpconUser: true,
		SessionID:    "sess-retry",
		Reason:       "Communication error",
	}
	if resp := expectSingleResponse(t, client); resp != want {
		t.Errorf("response: got %+v, want %+v", resp, want)
	}
	if _, exists := am.pidToSessionMap[4200].Requests["req-retry"]; exists {
		t.Error("request was not deregistered")
	}
}

// TestHandleSudoApprovalRequest_LocalSudoRegistersNothing checks a sudo outside any
// tracked session is answered on the spot and registers nothing—no request, and no
// completion channel for a waiter that never exists.
func TestHandleSudoApprovalRequest_LocalSudoRegistersNothing(t *testing.T) {
	am := newTestAuthManager()
	data, err := json.Marshal(SudoApprovalRequest{
		RequestID: "req-local",
		Type:      "sudo_approval",
		Username:  "alice",
		PID:       999999,
	})
	require.NoError(t, err)
	client, server := net.Pipe()

	go am.handleSudoRequest(server) // Driven through the owner, since that is what closes now.
	_, err = client.Write(data)
	require.NoError(t, err)

	resp := expectSingleResponse(t, client)
	assert.True(t, resp.Approved, "local sudo is approved while block_local_sudo is off")
	assert.False(t, resp.IsAlpconUser, "a sudo outside every tracked session is not an Alpacon user")
	assert.Empty(t, am.completionChannels, "completion channels left behind")
	assert.Empty(t, am.pidToSessionMap, "tracker entries left behind")
}

func TestRemovePIDCommandMapping_DeniesPendingRequests(t *testing.T) {
	am := newTestAuthManager()
	req := SudoApprovalRequest{RequestID: "req-cmd", Username: "bob", PID: 8888}
	client := registerPipeRequest(am, req)
	session := am.pidToSessionMap[8888]
	session.Kind = TrackerKindCommand
	session.SessionID = ""
	session.CommandID = "cmd-1"

	go am.RemovePIDCommandMapping(8888, "cmd-1")

	want := SudoApprovalResponse{
		RequestID: "req-cmd",
		Type:      "sudo_approval_response",
		Username:  "bob",
		PID:       8888,
		Reason:    "Session ended",
	}
	if resp := expectSingleResponse(t, client); resp != want {
		t.Errorf("response: got %+v, want %+v", resp, want)
	}
}

type closeTrackingConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *closeTrackingConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestHandleSudoRequest_ClosesConnectionWhenReadFails(t *testing.T) {
	am := newTestAuthManager()
	client, server := net.Pipe()
	conn := &closeTrackingConn{Conn: server}
	require.NoError(t, client.Close()) // Makes the handler's first Read fail.

	am.handleSudoRequest(conn)

	assert.True(t, conn.isClosed(), "connection was left open after the read failed")
}

func TestHandleSudoRequest_ClosesConnectionOnEveryPath(t *testing.T) {
	// Every payload here leaves handleSudoRequest by a different return, and each
	// of those returns gave up its own Close call to the deferred one.
	tests := []struct {
		name         string
		payload      string
		wantResponse bool
	}{
		{name: "malformed JSON", payload: "{"},
		{name: "missing type", payload: `{"username":"alice"}`},
		{name: "unknown type", payload: `{"type":"nope"}`},
		{name: "check_user with a malformed body", payload: `{"type":"check_user","pid":"not-an-int"}`, wantResponse: true},
		{name: "check_user with no session", payload: `{"type":"check_user","username":"alice","pid":4242,"ppid":1}`, wantResponse: true},
		{name: "sudo_approval with a malformed body", payload: `{"type":"sudo_approval","pid":"not-an-int"}`, wantResponse: true},
		{name: "session_event with no username", payload: `{"type":"session_event","service":"sshd","pid":4242}`, wantResponse: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am := newTestAuthManager()
			client, server := net.Pipe()
			conn := &closeTrackingConn{Conn: server}

			done := make(chan struct{})
			go func() {
				am.handleSudoRequest(conn)
				close(done)
			}()

			_, err := client.Write([]byte(tt.payload))
			require.NoError(t, err)

			// Without this a regression hangs until the suite-wide panic instead of failing here.
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			data, err := io.ReadAll(client)
			require.NoError(t, err, "the PAM side never saw EOF, so the handler left the connection open")
			if tt.wantResponse {
				assert.NotEmpty(t, data, "the handler closed without answering, so PAM has to time out instead of failing open")
			} else {
				assert.Empty(t, data)
			}

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("handleSudoRequest did not return")
			}
			assert.True(t, conn.isClosed(), "connection was left open")
			_ = client.Close()
		})
	}
}

// readErrConn fails every Read while leaving Write to the real connection, so a
// test can watch what the handler answers on the read-failure path.
type readErrConn struct{ *closeTrackingConn }

func (readErrConn) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type panicOnReadConn struct{ *closeTrackingConn }

func (panicOnReadConn) Read([]byte) (int, error) { panic("read exploded") }

func TestHandleSudoRequest_AnswersBeforeClosingWhenReadFails(t *testing.T) {
	am := newTestAuthManager()
	client, server := net.Pipe()
	conn := readErrConn{&closeTrackingConn{Conn: server}}

	done := make(chan struct{})
	go func() {
		am.handleSudoRequest(conn)
		close(done)
	}()

	// Without this a regression hangs until the suite-wide panic instead of failing here.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, err := io.ReadAll(client)
	require.NoError(t, err, "the PAM side never saw EOF, so the handler left the connection open")

	var resp IsAlpconResponse
	require.NoError(t, json.Unmarshal(data, &resp), "a request that cannot be read still has to be answered, or PAM waits out its own timeout")
	assert.False(t, resp.IsAlpconUser, "an unreadable request must not be answered as an Alpacon session")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleSudoRequest did not return")
	}
	assert.True(t, conn.isClosed(), "connection was left open after the read failed")
	_ = client.Close()
}

func TestHandleSudoRequest_ClosesConnectionOnPanic(t *testing.T) {
	am := newTestAuthManager()
	client, server := net.Pipe()
	conn := panicOnReadConn{&closeTrackingConn{Conn: server}}

	am.handleSudoRequest(conn) // The handler's recover is what keeps the panic from failing this test.

	assert.True(t, conn.isClosed(), "a panicking handler left the descriptor open")
	_ = client.Close()
}

// blockingWriteConn parks the first Write until release is closed, holding a
// response in flight while the test drives the waiter out.
type blockingWriteConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingWriteConn) Write(b []byte) (int, error) {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Conn.Write(b)
}

// TestHandleSudoApprovalRequest_ShutdownWaitsForTakenResponse pins the handover the
// deferred close depends on. HandleSudoApprovalResponse deregisters the request
// before it writes, so a shutdown landing in that window finds nothing pending and
// the waiter must still not close on a response already going out.
func TestHandleSudoApprovalRequest_ShutdownWaitsForTakenResponse(t *testing.T) {
	// Registration happens before the post, so a served request is one that can be taken.
	registered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(registered)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	am := newTestAuthManager()
	ctx, cancel := context.WithCancel(context.Background())
	am.ctx = ctx
	am.session = &scheduler.Session{BaseURL: srv.URL, Client: http.DefaultClient}
	am.pidToSessionMap[4200] = &SessionInfo{
		Kind:      TrackerKindWebsh,
		SessionID: "sess-shutdown",
		PID:       4200,
		Requests:  make(map[string]*SudoRequest),
	}

	data, err := json.Marshal(SudoApprovalRequest{
		RequestID: "req-shutdown",
		Type:      "sudo_approval",
		Username:  "alice",
		PID:       424242,
		PPID:      4200,
		Command:   "sudo reboot",
	})
	require.NoError(t, err)

	client, server := net.Pipe()
	conn := &blockingWriteConn{
		Conn:    server,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	go am.handleSudoRequest(conn)
	_, err = client.Write(data)
	require.NoError(t, err)

	type readResult struct {
		resp SudoApprovalResponse
		err  error
	}
	results := make(chan readResult, 1)
	go func() {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		var resp SudoApprovalResponse
		err := json.NewDecoder(client).Decode(&resp)
		results <- readResult{resp: resp, err: err}
	}()

	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the server")
	}

	go func() {
		_ = am.HandleSudoApprovalResponse(SudoApprovalResponse{
			RequestID: "req-shutdown",
			Type:      "sudo_approval_response",
			Username:  "alice",
			Approved:  true,
		})
	}()

	select {
	case <-conn.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the response write never started")
	}

	cancel()
	time.Sleep(100 * time.Millisecond) // Long enough for the waiter to close, if it is going to.
	close(conn.release)

	got := <-results
	require.NoError(t, got.err, "the approved response never reached the PAM client")
	assert.True(t, got.resp.Approved, "response: got %+v", got.resp)
}

// TestDenyPendingRequests_StalledPeerDoesNotDelayTheRest pins what
// authSocketHandoverTimeout claims: a waiter's handover bound has to outlive one
// bounded write, not a whole batch of them. A peer that stopped reading holds up
// its own request only, so the next request's waiter is released well inside its
// bound instead of returning and closing a connection the deny loop has yet to
// reach.
func TestDenyPendingRequests_StalledPeerDoesNotDelayTheRest(t *testing.T) {
	am := newTestAuthManager()

	stalledClient, stalledServer := net.Pipe()
	defer func() { _ = stalledClient.Close() }()
	stalled := &blockingWriteConn{
		Conn:    stalledServer,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	stalledDone := registerCompletionChannel(am, "req-stalled")
	nextDone := registerCompletionChannel(am, "req-next")

	pending := []*SudoRequest{
		{Connection: stalled, Request: SudoApprovalRequest{RequestID: "req-stalled", Username: "alice"}},
		{Connection: server, Request: SudoApprovalRequest{RequestID: "req-next", Username: "bob"}},
	}
	go am.denyPendingRequests(pending, "Session ended")

	select {
	case <-stalled.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled request's write never started")
	}

	select {
	case <-nextDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the second request's waiter was held behind the stalled peer's write")
	}

	// Let the stalled write through so the batch finishes on its own rather than on
	// the write deadline.
	go func() { _, _ = io.Copy(io.Discard, stalledClient) }()
	close(stalled.release)

	select {
	case <-stalledDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled request never signaled once its write went through")
	}
}
