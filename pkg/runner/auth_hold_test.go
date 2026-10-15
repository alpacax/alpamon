package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	holdTestSession = "sess-hold"
	holdTestRef     = "0f3c2a7e-9b1d-4c55-8e2f-1a2b3c4d5e6f"
	holdTestPPID    = 4300
)

// fakeAlpacon answers the agent's REST calls in process, so the tests run
// inside a synctest bubble with no network goroutine to keep the clock from
// advancing.
type fakeAlpacon struct {
	mu    sync.Mutex
	posts []recordedPost
	// approvalBody is the body of the answer to the sudo-approval post.
	approvalBody string
	// onApproval runs before the sudo-approval post is answered.
	onApproval func()
}

type recordedPost struct {
	path string
	body map[string]any
}

func (f *fakeAlpacon) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)

	f.mu.Lock()
	f.posts = append(f.posts, recordedPost{path: r.URL.Path, body: body})
	answer := "{}"
	onApproval := f.onApproval
	approval := strings.HasSuffix(r.URL.Path, "/sudo-approval/") || r.URL.Path == "/api/sudo/approval/"
	if approval {
		answer = f.approvalBody
	}
	f.mu.Unlock()

	if onApproval != nil && approval {
		onApproval()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(answer)),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

func (f *fakeAlpacon) recorded() []recordedPost {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedPost(nil), f.posts...)
}

func (f *fakeAlpacon) postsTo(suffix string) []recordedPost {
	var out []recordedPost
	for _, p := range f.recorded() {
		if strings.HasSuffix(p.path, suffix) {
			out = append(out, p)
		}
	}
	return out
}

// newHoldTestManager returns a manager with one tracked Websh session and a
// fake server. Call it inside the synctest bubble.
func newHoldTestManager(t *testing.T, server *fakeAlpacon) *AuthManager {
	t.Helper()
	am := newTestAuthManager()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	am.ctx, am.cancel = ctx, cancel
	am.session = &scheduler.Session{BaseURL: "http://alpacon.test", Client: &http.Client{Transport: server}}
	am.pidToSessionMap[holdTestPPID] = &SessionInfo{
		Kind:      TrackerKindWebsh,
		SessionID: holdTestSession,
		PID:       holdTestPPID,
		Requests:  make(map[string]*SudoRequest),
	}
	return am
}

func holdTestRequest(id string, holdCapable bool) SudoApprovalRequest {
	return SudoApprovalRequest{
		RequestID:   id,
		Type:        "sudo_approval",
		Username:    "alice",
		Groupname:   "alpacon",
		PID:         424242,
		PPID:        holdTestPPID,
		Command:     "systemctl restart nginx",
		RunasUser:   "root",
		HoldCapable: holdCapable,
	}
}

// pamClient plays the PAM module's side of auth.sock: it sends one request and
// collects everything alpamon writes until alpamon closes.
type pamClient struct {
	conn  net.Conn
	mu    sync.Mutex
	got   bytes.Buffer
	lines chan string
	done  chan struct{}
}

// recordingConn is alpamon's end of the socket; it records every write so a
// test can prove nothing was written after the client left.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
	// onWrite, when set, runs before each write.
	onWrite func()
}

func (c *recordingConn) Write(b []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite()
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recordingConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func startPAMClient(t *testing.T, am *AuthManager, req SudoApprovalRequest) (*pamClient, *recordingConn) {
	t.Helper()
	return startPAMClientWith(t, am, req, nil)
}

// startPAMClientWith is startPAMClient with a hook that runs before each of
// alpamon's writes.
func startPAMClientWith(t *testing.T, am *AuthManager, req SudoApprovalRequest, onWrite func()) (*pamClient, *recordingConn) {
	t.Helper()
	client, server := net.Pipe()
	rec := &recordingConn{Conn: server, onWrite: onWrite}
	go am.handleSudoRequest(rec)

	data, err := json.Marshal(req)
	require.NoError(t, err)
	_, err = client.Write(data)
	require.NoError(t, err)

	pc := &pamClient{conn: client, lines: make(chan string, 8), done: make(chan struct{})}
	go func() {
		defer close(pc.done)
		r := bufio.NewReader(client)
		for {
			line, err := r.ReadString('\n')
			pc.mu.Lock()
			pc.got.WriteString(line)
			pc.mu.Unlock()
			if line != "" && err == nil {
				pc.lines <- line
			}
			if err != nil {
				return
			}
		}
	}()
	return pc, rec
}

// output waits for alpamon to close and returns everything it wrote.
func (pc *pamClient) output(t *testing.T) string {
	t.Helper()
	synctest.Wait()
	select {
	case <-pc.done:
	default:
		require.Fail(t, "alpamon did not close the connection")
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.got.String()
}

func (pc *pamClient) interim(t *testing.T) string {
	t.Helper()
	synctest.Wait()
	select {
	case line := <-pc.lines:
		return line
	default:
		require.Fail(t, "no interim frame")
		return ""
	}
}

func pendingBody(waitSeconds int) string {
	return `{"status":"approval_pending","approval_request":"` + holdTestRef +
		`","expires_at":"2026-10-15T10:05:00Z","wait_seconds":` + itoa(waitSeconds) +
		`,"hold_reason":"SUDO_INTENT_DEVIATION"}`
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func marshalResponse(t *testing.T, resp SudoApprovalResponse) string {
	t.Helper()
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	return string(b)
}

func serverVerdict(req SudoApprovalRequest, approved bool, code string) SudoApprovalResponse {
	return SudoApprovalResponse{
		RequestID: req.RequestID,
		Type:      "sudo_approval_response",
		Username:  req.Username,
		Groupname: req.Groupname,
		Command:   req.Command,
		SessionID: holdTestSession,
		Approved:  approved,
		ErrorCode: code,
	}
}

const wantInterim = `{"type":"sudo_approval_pending","request_ref":"` + holdTestRef +
	`","wait_seconds":300,"expires_at":"2026-10-15T10:05:00Z","hold_reason":"SUDO_INTENT_DEVIATION"}` + "\n"

// A request without hold_capable is forwarded without the key and answered with
// the server's single object, exactly as before.
func TestHold_NonHoldRequestUnchanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: `{"status":"mfa_required"}`}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("101", false)
		pc, _ := startPAMClient(t, am, req)
		synctest.Wait()

		posts := server.postsTo("/sudo-approval/")
		require.Len(t, posts, 1)
		assert.Equal(t, "/api/websh/sessions/"+holdTestSession+"/sudo-approval/", posts[0].path)
		assert.NotContains(t, posts[0].body, "hold_capable")
		assert.Equal(t, "root", posts[0].body["runas_user"])

		verdict := SudoApprovalResponse{RequestID: "101", Type: "sudo_approval_response", Username: "alice", SessionID: holdTestSession, Approved: true}
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, marshalResponse(t, verdict), pc.output(t))
	})
}

// Without a verdict a request that was not held times out at 30 s with the
// code-less deny it always had.
func TestHold_NonHoldTimeoutUnchanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: `{}`}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("102", false)
		pc, _ := startPAMClient(t, am, req)

		time.Sleep(sudoApprovalResponseTimeout)
		want := SudoApprovalResponse{
			RequestID: "102", Type: "sudo_approval_response", Username: "alice", Groupname: "alpacon",
			PID: req.PID, PPID: req.PPID, Command: req.Command, IsAlpconUser: true,
			SessionID: holdTestSession, Reason: "Response timeout",
		}
		assert.Equal(t, marshalResponse(t, want), pc.output(t))
		assert.NotContains(t, pc.output(t), "error_code")
	})
}

func TestHold_PendingThenApproved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("103", true)
		pc, _ := startPAMClient(t, am, req)

		assert.Equal(t, wantInterim, pc.interim(t))
		posts := server.postsTo("/sudo-approval/")
		require.Len(t, posts, 1)
		assert.Equal(t, true, posts[0].body["hold_capable"])
		assert.Equal(t, "root", posts[0].body["runas_user"])

		// Well past the usual 30 s: the hold extended the wait.
		time.Sleep(2 * time.Minute)
		verdict := serverVerdict(req, true, "")
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, wantInterim+marshalResponse(t, verdict), pc.output(t))
		assert.Empty(t, server.postsTo("/wait-ended/"))
	})
}

func TestHold_PendingThenRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("104", true)
		pc, _ := startPAMClient(t, am, req)
		pc.interim(t)

		verdict := serverVerdict(req, false, "SUDO_APPROVAL_REJECTED")
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, wantInterim+marshalResponse(t, verdict), pc.output(t))
	})
}

// With no verdict, alpamon answers the coded pending deny at wait_seconds+45
// and tells the server the wait ended.
func TestHold_DeadlineAnswersPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(10)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("105", true)
		pc, _ := startPAMClient(t, am, req)
		pc.interim(t)

		time.Sleep(10*time.Second + holdGrace - time.Millisecond)
		synctest.Wait()
		select {
		case <-pc.done:
			require.Fail(t, "answered before wait_seconds+45")
		default:
		}

		time.Sleep(time.Millisecond)
		out := pc.output(t)
		require.True(t, strings.HasPrefix(out, `{"type":"sudo_approval_pending"`), out)
		var final SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(out[strings.IndexByte(out, '\n')+1:]), &final))
		assert.False(t, final.Approved)
		assert.Equal(t, "SUDO_APPROVAL_PENDING", final.ErrorCode)
		assert.Equal(t, "105", final.RequestID)

		synctest.Wait()
		ended := server.postsTo("/wait-ended/")
		require.Len(t, ended, 1)
		assert.Equal(t, "/api/websh/sessions/"+holdTestSession+"/sudo-approval/"+holdTestRef+"/wait-ended/", ended[0].path)
	})
}

// The client closing mid-wait ends the wait: nothing more is written, the
// server is told, and a late verdict finds nothing to answer.
func TestHold_PeerCloseEndsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("106", true)
		pc, rec := startPAMClient(t, am, req)
		pc.interim(t)

		time.Sleep(3 * time.Second)
		require.NoError(t, pc.conn.Close())
		synctest.Wait()

		ended := server.postsTo("/wait-ended/")
		require.Len(t, ended, 1)
		assert.Equal(t, "/api/websh/sessions/"+holdTestSession+"/sudo-approval/"+holdTestRef+"/wait-ended/", ended[0].path)
		assert.Equal(t, map[string]any{
			"request_id": "106",
			"command":    req.Command,
			"session_id": holdTestSession,
		}, ended[0].body)
		assert.Equal(t, 1, rec.writeCount(), "only the interim frame may be written")

		assert.Error(t, am.HandleSudoApprovalResponse(serverVerdict(req, true, "")))
		assert.Equal(t, 1, rec.writeCount(), "nothing may be written after the client closed")
	})
}

// A verdict that carries the held request's id but another command or session
// is dropped; the held request keeps waiting for its own.
func TestHold_MismatchedVerdictDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("107", true)
		pc, _ := startPAMClient(t, am, req)
		pc.interim(t)

		other := serverVerdict(req, true, "")
		other.Command = "rm -rf /srv/data"
		assert.Error(t, am.HandleSudoApprovalResponse(other))

		otherSession := serverVerdict(req, true, "")
		otherSession.SessionID = "sess-other"
		assert.Error(t, am.HandleSudoApprovalResponse(otherSession))

		synctest.Wait()
		select {
		case <-pc.done:
			require.Fail(t, "a mismatched verdict answered the request")
		default:
		}

		verdict := serverVerdict(req, true, "")
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, wantInterim+marshalResponse(t, verdict), pc.output(t))
	})
}

// After a held wait ended, a new request reusing its id (the sudo pid) must not
// take the ended wait's late verdict, but still takes its own.
func TestHold_EndedWaitVerdictNotAppliedToReusedID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		held := holdTestRequest("108", true)
		pc, _ := startPAMClient(t, am, held)
		pc.interim(t)
		require.NoError(t, pc.conn.Close())
		synctest.Wait()

		server.mu.Lock()
		server.approvalBody = `{"status":"mfa_required"}`
		server.mu.Unlock()
		reused := holdTestRequest("108", false)
		reused.Command = "cat /etc/shadow"
		pc2, _ := startPAMClient(t, am, reused)
		synctest.Wait()

		assert.Error(t, am.HandleSudoApprovalResponse(serverVerdict(held, true, "")), "the ended wait's verdict was applied")

		own := SudoApprovalResponse{RequestID: "108", Type: "sudo_approval_response", Command: reused.Command, SessionID: holdTestSession, Approved: false, ErrorCode: "SUDO_NO_AUTHORITY"}
		require.NoError(t, am.HandleSudoApprovalResponse(own))
		assert.Equal(t, marshalResponse(t, own), pc2.output(t))
	})
}

// A second hold-capable request for the same command while one waits is
// answered at once and never forwarded.
func TestHold_AlreadyWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		first := holdTestRequest("109", true)
		pc, _ := startPAMClient(t, am, first)
		pc.interim(t)

		second := holdTestRequest("110", true)
		pc2, _ := startPAMClient(t, am, second)
		out := pc2.output(t)
		var resp SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(out), &resp))
		assert.False(t, resp.Approved)
		assert.Equal(t, "SUDO_APPROVAL_ALREADY_WAITING", resp.ErrorCode)
		assert.NotContains(t, out, "\n", "a single object, no interim frame")
		assert.Len(t, server.postsTo("/sudo-approval/"), 1, "the second request was forwarded")

		// Another command is not the same wait.
		third := holdTestRequest("111", true)
		third.Command = "systemctl restart postgresql"
		startPAMClient(t, am, third)
		synctest.Wait()
		assert.Len(t, server.postsTo("/sudo-approval/"), 2)

		require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(first, true, "")))
		pc.output(t)
		third.SessionID = holdTestSession
		require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(third, true, "")))
	})
}

// A client that did not offer to wait never gets an interim frame: a pending
// answer becomes the coded deny, as a single object.
func TestHold_PendingWithoutHoldCapableDenies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("112", false)
		pc, _ := startPAMClient(t, am, req)

		out := pc.output(t)
		assert.NotContains(t, out, "sudo_approval_pending")
		assert.NotContains(t, out, "\n")
		var resp SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(out), &resp))
		assert.False(t, resp.Approved)
		assert.Equal(t, "SUDO_APPROVAL_PENDING", resp.ErrorCode)

		synctest.Wait()
		assert.Len(t, server.postsTo("/wait-ended/"), 1)
	})
}

// A verdict that lands before alpamon has read the pending answer goes out
// alone: an interim frame never follows the final one.
func TestHold_NoInterimAfterFinal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var am *AuthManager
		var req SudoApprovalRequest
		var verdict SudoApprovalResponse
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		server.onApproval = func() {
			require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		}
		am = newHoldTestManager(t, server)
		req = holdTestRequest("113", true)
		verdict = serverVerdict(req, true, "")
		pc, _ := startPAMClient(t, am, req)

		assert.Equal(t, marshalResponse(t, verdict), pc.output(t))
	})
}

func TestWriteInterimFrame_SkipsAfterFinal(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	req := &SudoRequest{Connection: server, final: true}
	written, err := writeInterimFrame(req, &sudoHold{ref: "ab", waitSeconds: 1, expiresAt: "2026-10-15T10:05:00Z"})
	assert.NoError(t, err)
	assert.False(t, written)
}

func TestParseApprovalPending(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		pending bool
		hold    *sudoHold
	}{
		{name: "empty", body: ``},
		{name: "old shape", body: `{"status":"mfa_required"}`},
		{name: "not json", body: `<html>`},
		{
			name: "full", body: pendingBody(300), pending: true,
			hold: &sudoHold{ref: holdTestRef, waitSeconds: 300, expiresAt: "2026-10-15T10:05:00Z", holdReason: "SUDO_INTENT_DEVIATION"},
		},
		{
			name:    "capped wait, offset expiry, server command form",
			body:    `{"status":"approval_pending","approval_request":"ab12cd34","expires_at":"2026-10-15T19:05:00+09:00","wait_seconds":900,"command":"mysql -p*** #k:1f"}`,
			pending: true,
			hold:    &sudoHold{ref: "ab12cd34", waitSeconds: maxHoldWaitSeconds, expiresAt: "2026-10-15T10:05:00Z", command: "mysql -p*** #k:1f"},
		},
		{
			name:    "unsafe hold reason dropped",
			body:    `{"status":"approval_pending","approval_request":"ab12","expires_at":"2026-10-15T10:05:00Z","wait_seconds":5,"hold_reason":"bad reason\n"}`,
			pending: true,
			hold:    &sudoHold{ref: "ab12", waitSeconds: 5, expiresAt: "2026-10-15T10:05:00Z"},
		},
		{name: "zero wait", body: `{"status":"approval_pending","approval_request":"ab12","wait_seconds":0}`, pending: true},
		{name: "float wait", body: `{"status":"approval_pending","approval_request":"ab12","wait_seconds":1.5}`, pending: true},
		{name: "string wait", body: `{"status":"approval_pending","approval_request":"ab12","wait_seconds":"30"}`, pending: true},
		{name: "missing ref", body: `{"status":"approval_pending","wait_seconds":30}`, pending: true},
		{name: "ref with a path", body: `{"status":"approval_pending","approval_request":"../x","wait_seconds":30}`, pending: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hold, pending := parseApprovalPending([]byte(tt.body))
			assert.Equal(t, tt.pending, pending)
			assert.Equal(t, tt.hold, hold)
		})
	}
}

// A missing or unparseable expires_at is filled in from wait_seconds.
func TestParseApprovalPending_ExpiryFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold, pending := parseApprovalPending([]byte(`{"status":"approval_pending","approval_request":"ab12","wait_seconds":60}`))
		require.True(t, pending)
		require.NotNil(t, hold)
		assert.Equal(t, time.Now().Add(time.Minute).UTC().Format(time.RFC3339), hold.expiresAt)
	})
}

// Two Alpacon users may share one host account: the same command from another
// session is not the same wait, and the server decides about it.
func TestHold_SameCommandInAnotherSessionIsForwarded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		am.pidToSessionMap[holdTestPPID+1] = &SessionInfo{
			Kind:      TrackerKindWebsh,
			SessionID: "sess-other",
			PID:       holdTestPPID + 1,
			Requests:  make(map[string]*SudoRequest),
		}
		first := holdTestRequest("120", true)
		pc, _ := startPAMClient(t, am, first)
		pc.interim(t)

		second := holdTestRequest("121", true)
		second.PPID = holdTestPPID + 1
		pc2, _ := startPAMClient(t, am, second)
		line := pc2.interim(t)
		assert.True(t, strings.HasPrefix(line, `{"type":"sudo_approval_pending"`), line)
		assert.Len(t, server.postsTo("/sudo-approval/"), 2)

		require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(first, true, "")))
		pc.output(t)
		verdict := serverVerdict(second, true, "")
		verdict.SessionID = "sess-other"
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		pc2.output(t)
	})
}

// A Websh verdict without the session it answers is not applied to a held
// request.
func TestHold_VerdictWithoutSessionDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("122", true)
		pc, rec := startPAMClient(t, am, req)
		pc.interim(t)

		noSession := serverVerdict(req, true, "")
		noSession.SessionID = ""
		assert.Error(t, am.HandleSudoApprovalResponse(noSession))
		synctest.Wait()
		assert.Equal(t, 1, rec.writeCount())

		require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(req, false, "SUDO_APPROVAL_REJECTED")))
		pc.output(t)
	})
}

// wait_seconds above 600 is capped, so alpamon answers at 645 s, ahead of the
// client's 660 s cap.
func TestHold_WaitCappedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(900)}
		am := newHoldTestManager(t, server)
		pc, _ := startPAMClient(t, am, holdTestRequest("123", true))
		assert.Equal(t, strings.Replace(wantInterim, `"wait_seconds":300`, `"wait_seconds":600`, 1), pc.interim(t))

		time.Sleep(645*time.Second - time.Millisecond)
		synctest.Wait()
		select {
		case <-pc.done:
			require.Fail(t, "answered before 645 s")
		default:
		}
		time.Sleep(time.Millisecond)
		assert.Contains(t, pc.output(t), `"error_code":"SUDO_APPROVAL_PENDING"`)
	})
}

// Stopping the agent mid-hold answers the coded pending deny and reports the
// end of the wait without holding up the shutdown.
func TestHold_ShutdownDuringHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("124", true)
		pc, _ := startPAMClient(t, am, req)
		pc.interim(t)

		am.cancel()
		out := pc.output(t)
		var final SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(out[strings.IndexByte(out, '\n')+1:]), &final))
		assert.False(t, final.Approved)
		assert.Equal(t, "SUDO_APPROVAL_PENDING", final.ErrorCode)

		synctest.Wait()
		assert.Len(t, server.postsTo("/wait-ended/"), 1)
	})
}

// The same command in the same session but as another run-as user is a
// different request: an ended wait's verdict is not applied to it.
func TestHold_EndedWaitVerdictNeedsSameRunasUser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		held := holdTestRequest("125", true)
		pc, _ := startPAMClient(t, am, held)
		pc.interim(t)
		require.NoError(t, pc.conn.Close())
		synctest.Wait()

		server.mu.Lock()
		server.approvalBody = `{"status":"mfa_required"}`
		server.mu.Unlock()
		reused := holdTestRequest("125", false)
		reused.RunasUser = "postgres"
		pc2, _ := startPAMClient(t, am, reused)
		synctest.Wait()

		// The new request's own verdict carries the same command and session, so
		// it cannot be told apart and is dropped too: the request ends on its
		// own timeout, fail-closed.
		assert.Error(t, am.HandleSudoApprovalResponse(serverVerdict(held, true, "")))
		time.Sleep(sudoApprovalResponseTimeout)
		assert.Contains(t, pc2.output(t), `"reason":"Response timeout"`)
	})
}

// A verdict racing the client's close settles one way: either the verdict was
// taken (and the wait was not reported as ended), or the wait ended and no
// verdict was written. Never both, never a write after the interim frame plus
// a wait-ended post.
func TestHold_VerdictRacesPeerClose(t *testing.T) {
	for i := range 25 {
		t.Run(itoa(i), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := &fakeAlpacon{approvalBody: pendingBody(300)}
				am := newHoldTestManager(t, server)
				req := holdTestRequest("126", true)
				pc, rec := startPAMClient(t, am, req)
				pc.interim(t)

				verdictErr := make(chan error, 1)
				go func() { verdictErr <- am.HandleSudoApprovalResponse(serverVerdict(req, true, "")) }()
				go func() { _ = pc.conn.Close() }()
				synctest.Wait()

				ended := len(server.postsTo("/wait-ended/"))
				writes := rec.writeCount()
				err := <-verdictErr
				assert.LessOrEqual(t, ended, 1)
				if ended == 1 {
					assert.Equal(t, 1, writes, "a verdict was written to a wait that ended")
					assert.Error(t, err)
				} else {
					assert.Equal(t, 2, writes, "the verdict was neither written nor the wait ended")
				}
			})
		})
	}
}

type scriptedReadConn struct {
	net.Conn
	reads chan error
}

func (c *scriptedReadConn) Read([]byte) (int, error) {
	err, ok := <-c.reads
	if !ok {
		return 0, net.ErrClosed
	}
	if err == nil {
		return 1, nil
	}
	return 0, err
}

func TestWatchPeerClose(t *testing.T) {
	tests := []struct {
		name  string
		reads []error
		gone  bool
	}{
		{name: "EOF", reads: []error{io.EOF}, gone: true},
		{name: "reset", reads: []error{syscall.ECONNRESET}, gone: true},
		{name: "stray bytes then EOF", reads: []error{nil, nil, io.EOF}, gone: true},
		{name: "closed by alpamon", reads: []error{net.ErrClosed}},
		{name: "deadline", reads: []error{syscall.ETIMEDOUT}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				conn := &scriptedReadConn{reads: make(chan error, len(tt.reads))}
				for _, r := range tt.reads {
					conn.reads <- r
				}
				gone := watchPeerClose(conn)
				synctest.Wait()
				select {
				case <-gone:
					assert.True(t, tt.gone, "reported a close that was not the peer's")
				default:
					assert.False(t, tt.gone, "missed the peer's close")
					close(conn.reads)
				}
			})
		})
	}
}

// The request id is the sudo pid, which the kernel reuses. The tests below
// reuse an id at each step of a hold and check the old request's verdict,
// signal, hold or cleanup never reaches the newer one.

// A pending answer for a client that cannot wait guards the id before the deny
// goes out, so no reuse can slip in between the answer and the guard.
func TestHold_NonHoldablePendingGuardsBeforeDeny(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("130", false)

		var guarded []bool
		pc, _ := startPAMClientWith(t, am, req, func() {
			am.mu.RLock()
			_, ok := am.endedHolds[req.RequestID]
			am.mu.RUnlock()
			guarded = append(guarded, ok)
		})

		assert.Contains(t, pc.output(t), `"error_code":"SUDO_APPROVAL_PENDING"`)
		assert.Equal(t, []bool{true}, guarded, "the deny was written before the id was guarded")
	})
}

// A newer request reuses the id while the old request's post is in flight: the
// old pending answer must not attach its hold to the newer request or write
// its interim frame there, and the old wait is reported as ended.
func TestHold_PendingAfterReuseDoesNotAttachToNewRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var posts int
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		server.onApproval = func() {
			server.mu.Lock()
			posts++
			first := posts == 1
			server.mu.Unlock()
			if first {
				<-release
			}
		}
		am := newHoldTestManager(t, server)
		old := holdTestRequest("131", true)
		pc, _ := startPAMClient(t, am, old)
		synctest.Wait()

		server.mu.Lock()
		server.approvalBody = `{"status":"mfa_required"}`
		server.mu.Unlock()
		reused := holdTestRequest("131", true)
		reused.Command = "systemctl restart postgresql"
		pc2, rec2 := startPAMClient(t, am, reused)
		synctest.Wait()
		assert.Empty(t, pc.output(t), "the displaced request was written to")

		close(release)
		synctest.Wait()

		assert.Zero(t, rec2.writeCount(), "the old interim frame went to the new request")
		newer := registeredRequest(am, "131")
		require.NotNil(t, newer)
		assert.Equal(t, reused.Command, newer.Request.Command)
		assert.Nil(t, newer.hold, "the old hold attached to the new request")
		// The newer request's post went out first and may share the old wait on
		// the server, so the old wait is left to the server's deadline.
		assert.Empty(t, server.postsTo("/wait-ended/"))

		assert.Error(t, am.HandleSudoApprovalResponse(serverVerdict(old, true, "")), "the old wait's verdict was applied")
		own := serverVerdict(reused, true, "")
		require.NoError(t, am.HandleSudoApprovalResponse(own))
		assert.Equal(t, marshalResponse(t, own), pc2.output(t))
	})
}

// A newer request reuses the id of a live hold: the old hold's close watcher
// and deadline must not take, deny or close the newer request.
func TestHold_OldWatcherAndDeadlineSpareReusedID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(10)}
		am := newHoldTestManager(t, server)
		old := holdTestRequest("132", true)
		pc, _ := startPAMClient(t, am, old)
		oldInterim := pc.interim(t)

		server.mu.Lock()
		server.approvalBody = pendingBody(300)
		server.mu.Unlock()
		reused := holdTestRequest("132", true)
		pc2, rec2 := startPAMClient(t, am, reused)
		assert.Equal(t, wantInterim, pc2.interim(t))
		assert.Equal(t, oldInterim, pc.output(t), "the displaced request got more than its interim frame")

		_ = pc.conn.Close()
		time.Sleep(10*time.Second + holdGrace)
		synctest.Wait()
		select {
		case <-pc2.done:
			require.Fail(t, "the old hold's watcher or deadline ended the new request")
		default:
		}
		assert.Equal(t, 1, rec2.writeCount())
		assert.Empty(t, server.postsTo("/wait-ended/"), "the same wait continues; nothing ended")

		verdict := serverVerdict(reused, true, "")
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, wantInterim+marshalResponse(t, verdict), pc2.output(t))
	})
}

// reuseConn registers a newer request under the same id at the first write or
// close: the moment between a take and its completion signal.
type reuseConn struct {
	net.Conn
	once  sync.Once
	reuse func()
}

func (c *reuseConn) Write(b []byte) (int, error) {
	c.once.Do(c.reuse)
	return c.Conn.Write(b)
}

func (c *reuseConn) Close() error {
	c.once.Do(c.reuse)
	return c.Conn.Close()
}

// Each taker signals the instance it took, never the one registered under the
// id by the time it signals.
func TestTakers_SignalOnlyTheTakenInstance(t *testing.T) {
	takers := map[string]func(am *AuthManager, old *SudoRequest){
		"verdict": func(am *AuthManager, old *SudoRequest) {
			_ = am.HandleSudoApprovalResponse(SudoApprovalResponse{RequestID: old.Request.RequestID, Type: "sudo_approval_response", SessionID: holdTestSession, Approved: true})
		},
		"deny": func(am *AuthManager, old *SudoRequest) {
			assert.True(t, am.finalizeRequest(old, "Response timeout"))
		},
		"abandon": func(am *AuthManager, old *SudoRequest) {
			am.abandonHeldRequest(old, &sudoHold{ref: holdTestRef}, "client closed the connection")
		},
	}
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			am := newTestAuthManager()
			req := SudoApprovalRequest{RequestID: "133", Username: "alice", PID: 133, SessionID: holdTestSession}
			session := &SessionInfo{Kind: TrackerKindWebsh, SessionID: holdTestSession, PID: 1, Requests: map[string]*SudoRequest{}}
			am.pidToSessionMap[1] = session

			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			go func() { _, _ = io.Copy(io.Discard, client) }()
			newerClient, newerServer := net.Pipe()
			defer func() { _ = newerClient.Close() }()
			newer := newSudoRequest(newerServer, req)

			conn := &reuseConn{Conn: server, reuse: func() {
				am.mu.Lock()
				session.Requests[req.RequestID] = newer
				am.mu.Unlock()
			}}
			old := newSudoRequest(conn, req)
			session.Requests[req.RequestID] = old

			take(am, old)

			assert.Len(t, old.done, 1, "the taken instance was not signaled")
			assert.Empty(t, newer.done, "the newer request's waiter was signaled")
			assert.Same(t, newer, registeredRequest(am, req.RequestID), "the newer request was taken")
			newer.writeMu.Lock()
			assert.False(t, newer.final, "the newer request was finalized")
			newer.writeMu.Unlock()
		})
	}
}

// After a held wait ended, a new held request reusing the id with the same
// command and session but another run-as user must not take the old verdict.
func TestHold_HeldReuseNeedsSameRunasUser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		old := holdTestRequest("134", true)
		pc, _ := startPAMClient(t, am, old)
		pc.interim(t)
		require.NoError(t, pc.conn.Close())
		synctest.Wait()

		reused := holdTestRequest("134", true)
		reused.RunasUser = "postgres"
		pc2, rec2 := startPAMClient(t, am, reused)
		pc2.interim(t)

		assert.Error(t, am.HandleSudoApprovalResponse(serverVerdict(old, true, "")), "the old run-as user's verdict was applied")
		synctest.Wait()
		assert.Equal(t, 1, rec2.writeCount(), "only the interim frame may be written")
		select {
		case <-pc2.done:
			require.Fail(t, "the stale verdict answered the new request")
		default:
		}
		am.cancel()
		pc2.output(t)
	})
}

// A held deploy Command request takes only a verdict naming its own Command.
func TestHold_SessionlessVerdictNeedsCommandID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		am.pidToSessionMap[holdTestPPID+2] = &SessionInfo{
			Kind:      TrackerKindCommand,
			CommandID: "cmd-1",
			PID:       holdTestPPID + 2,
			Requests:  make(map[string]*SudoRequest),
		}
		req := holdTestRequest("135", true)
		req.PPID = holdTestPPID + 2
		pc, rec := startPAMClient(t, am, req)
		pc.interim(t)
		assert.Len(t, server.postsTo("/api/sudo/approval/"), 1)

		verdict := serverVerdict(req, true, "")
		verdict.SessionID = ""
		verdict.CommandID = "cmd-2"
		assert.Error(t, am.HandleSudoApprovalResponse(verdict), "another Command's verdict was applied")
		verdict.CommandID = ""
		assert.Error(t, am.HandleSudoApprovalResponse(verdict), "a verdict without a Command was applied")
		synctest.Wait()
		assert.Equal(t, 1, rec.writeCount())

		verdict.CommandID = "cmd-1"
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, wantInterim+marshalResponse(t, verdict), pc.output(t))
	})
}

// A late verdict naming another session is not applied to a request that
// reuses its id, held or not: the id alone is the sudo pid.
func TestVerdict_NeedsTheRequestsSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: `{"status":"mfa_required"}`}
		am := newHoldTestManager(t, server)
		req := holdTestRequest("140", false)
		pc, rec := startPAMClient(t, am, req)
		synctest.Wait()

		late := serverVerdict(req, true, "")
		late.SessionID = "sess-other"
		assert.Error(t, am.HandleSudoApprovalResponse(late))
		late.SessionID = ""
		assert.Error(t, am.HandleSudoApprovalResponse(late))
		synctest.Wait()
		assert.Zero(t, rec.writeCount(), "a verdict for another session was written")

		own := serverVerdict(req, false, "SUDO_APPROVAL_REJECTED")
		require.NoError(t, am.HandleSudoApprovalResponse(own))
		assert.Equal(t, marshalResponse(t, own), pc.output(t))
	})
}

// A deploy Command request takes a verdict without a command id, as the
// server sends it, but not one naming another Command or a Websh session.
func TestVerdict_SessionlessNeedsItsCommand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: `{"status":"mfa_required"}`}
		am := newHoldTestManager(t, server)
		am.pidToSessionMap[holdTestPPID+2] = &SessionInfo{
			Kind:      TrackerKindCommand,
			CommandID: "cmd-1",
			PID:       holdTestPPID + 2,
			Requests:  make(map[string]*SudoRequest),
		}
		req := holdTestRequest("141", false)
		req.PPID = holdTestPPID + 2
		pc, rec := startPAMClient(t, am, req)
		synctest.Wait()

		verdict := serverVerdict(req, true, "")
		assert.Error(t, am.HandleSudoApprovalResponse(verdict), "a Websh session's verdict was applied")
		verdict.SessionID = ""
		verdict.CommandID = "cmd-2"
		assert.Error(t, am.HandleSudoApprovalResponse(verdict), "another Command's verdict was applied")
		synctest.Wait()
		assert.Zero(t, rec.writeCount())

		verdict.CommandID = ""
		require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		assert.Equal(t, marshalResponse(t, verdict), pc.output(t))
	})
}

// A held request displaced by a different wait (here another run-as user) has
// its end reported before the newer request is forwarded, so the server never
// ends the newer wait with it.
func TestHold_DisplacedWaitEndsBeforeNewPost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		old := holdTestRequest("142", true)
		pc, _ := startPAMClient(t, am, old)
		pc.interim(t)

		reused := holdTestRequest("142", true)
		reused.RunasUser = "postgres"
		pc2, _ := startPAMClient(t, am, reused)
		pc2.interim(t)

		var order []string
		for _, p := range server.recorded() {
			order = append(order, p.path)
		}
		approval := "/api/websh/sessions/" + holdTestSession + "/sudo-approval/"
		assert.Equal(t, []string{approval, approval + holdTestRef + "/wait-ended/", approval}, order)
		assert.Equal(t, old.Command, server.postsTo("/wait-ended/")[0].body["command"])
		assert.Equal(t, wantInterim, pc.output(t), "the displaced request got more than its interim frame")
	})
}

// Tearing down a session with a held request guards its id and reports the
// wait as ended, so the server's late verdict cannot reach a reused id and
// the server's wait does not run to its deadline.
func TestHold_SessionTeardownEndsHeldWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300)}
		am := newHoldTestManager(t, server)
		held := holdTestRequest("143", true)
		pc, _ := startPAMClient(t, am, held)
		pc.interim(t)

		am.RemovePIDSessionMapping(holdTestPPID)
		assert.Contains(t, pc.output(t), `"reason":"Session ended"`)
		synctest.Wait()
		assert.Len(t, server.postsTo("/wait-ended/"), 1)
		am.mu.RLock()
		_, guarded := am.endedHolds["143"]
		am.mu.RUnlock()
		assert.True(t, guarded, "the torn-down wait's id is not guarded")
	})
}
