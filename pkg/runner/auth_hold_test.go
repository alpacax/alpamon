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
	if strings.HasSuffix(r.URL.Path, "/sudo-approval/") {
		answer = f.approvalBody
	}
	f.mu.Unlock()

	if onApproval != nil && strings.HasSuffix(r.URL.Path, "/sudo-approval/") {
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
	am.ctx = ctx
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
}

func (c *recordingConn) Write(b []byte) (int, error) {
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
	client, server := net.Pipe()
	rec := &recordingConn{Conn: server}
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
		t.Fatal("alpamon did not close the connection")
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
		t.Fatal("no interim frame")
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

		verdict := SudoApprovalResponse{RequestID: "101", Type: "sudo_approval_response", Username: "alice", Approved: true}
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
			t.Fatal("answered before wait_seconds+45")
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
			t.Fatal("a mismatched verdict answered the request")
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

		own := SudoApprovalResponse{RequestID: "108", Type: "sudo_approval_response", Command: reused.Command, Approved: false, ErrorCode: "SUDO_NO_AUTHORITY"}
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
