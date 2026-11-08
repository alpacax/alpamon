package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSudoNonceEndedAttemptDoesNotMatchSuccessor(t *testing.T) {
	var original SudoApprovalRequest
	require.NoError(t, json.Unmarshal([]byte(`{"request_id":"4100","session_id":"session","command":"same","approval_nonce":"11111111111111111111111111111111"}`), &original))
	old := newSudoRequest(nil, original)
	session := &SessionInfo{Requests: map[string]*SudoRequest{"4100": old}}
	am := &AuthManager{pidToSessionMap: map[int]*SessionInfo{4000: session}}
	require.True(t, am.finalizeRequest(old, "Response timeout"))
	var next SudoApprovalRequest
	require.NoError(t, json.Unmarshal([]byte(`{"request_id":"4100","session_id":"session","command":"same","approval_nonce":"22222222222222222222222222222222"}`), &next))
	replacement := newSudoRequest(nil, next)
	replacement.posting = true
	session.Requests["4100"] = replacement
	var late SudoApprovalResponse
	require.NoError(t, json.Unmarshal([]byte(`{"request_id":"4100","session_id":"session","command":"same","approved":true,"approval_nonce":"11111111111111111111111111111111"}`), &late))
	assert.Error(t, am.HandleSudoApprovalResponse(late))
	assert.Empty(t, replacement.early)
	assert.Same(t, replacement, session.Requests["4100"])
}

func TestSudoNonceMatchingAndSettlement(t *testing.T) {
	for _, posting := range []bool{false, true} {
		for _, mode := range []string{"match", "mismatch", "missing", "legacy"} {
			if mode == "missing" && posting {
				continue
			}
			t.Run(fmt.Sprintf("%s/posting=%t", mode, posting), func(t *testing.T) {
				client, socket := net.Pipe()
				t.Cleanup(func() { _ = client.Close(); _ = socket.Close() })
				received := make(chan []byte, 1)
				go func() { b, _ := io.ReadAll(client); received <- b }()
				req := newSudoRequest(socket, SudoApprovalRequest{RequestID: "1", SessionID: "session", ApprovalNonce: strings.Repeat("a", 32)})
				req.posting = posting
				session := &SessionInfo{Requests: map[string]*SudoRequest{"1": req}}
				am := &AuthManager{pidToSessionMap: map[int]*SessionInfo{1: session}}
				response := SudoApprovalResponse{RequestID: "1", SessionID: "session", Approved: true}
				switch mode {
				case "match":
					response.ApprovalNonce = req.Request.ApprovalNonce
					response.RequestID = "different"
					response.SessionID = "different"
					req.hold = &sudoHold{command: "different"}
					am.saturatedEndedIDs = map[string]time.Time{"1": time.Now().Add(time.Hour)}
				case "mismatch":
					response.ApprovalNonce = strings.Repeat("b", 32)
				case "missing":
					req.nonceBound = true
				}
				err := am.HandleSudoApprovalResponse(response)
				if mode == "mismatch" || mode == "missing" {
					require.Error(t, err)
					assert.Same(t, req, session.Requests["1"])
					assert.Empty(t, req.early)
					return
				}
				require.NoError(t, err)
				if posting {
					got, ok := am.settlePost(req, nil, []byte(`{}`))
					require.True(t, ok)
					assert.Equal(t, response, got)
					require.NoError(t, am.deliverVerdict(req, got))
				}
				var delivered SudoApprovalResponse
				require.NoError(t, json.Unmarshal(<-received, &delivered))
				response.ApprovalNonce = ""
				assert.Equal(t, response, delivered)
				assert.Empty(t, session.Requests)
				assert.NotEmpty(t, am.endedHolds["1"])
			})
		}
	}
}

func TestSudoNonceHeldRerunAndRequestBody(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalAnswer: func(body map[string]any) string {
			var answer map[string]any
			require.NoError(t, json.Unmarshal([]byte(pendingBody(300)), &answer))
			answer["approval_nonce"] = body["approval_nonce"]
			raw, err := json.Marshal(answer)
			require.NoError(t, err)
			return string(raw)
		}}
		am := newHoldTestManager(t, server)
		request := holdTestRequest("4100", true)
		request.ApprovalNonce = "client supplied"
		first, _ := startPAMClient(t, am, request)
		require.Contains(t, first.interim(t), "approval_pending")
		posts := server.postsTo("/sudo-approval/")
		require.Len(t, posts, 1)
		firstNonce, ok := posts[0].body["approval_nonce"].(string)
		require.True(t, ok)
		require.Regexp(t, `^[0-9a-f]{32}$`, firstNonce)
		am.mu.Lock()
		old := am.findRequestLocked("4100")
		am.mu.Unlock()
		require.True(t, am.finalizeRequest(old, "Response timeout"))
		assert.Contains(t, first.output(t), `"approved":false`)
		second, _ := startPAMClient(t, am, request)
		require.Contains(t, second.interim(t), "approval_pending")
		posts = server.postsTo("/sudo-approval/")
		require.Len(t, posts, 2)
		secondNonce, ok := posts[1].body["approval_nonce"].(string)
		require.True(t, ok)
		require.Regexp(t, `^[0-9a-f]{32}$`, secondNonce)
		require.NotEqual(t, firstNonce, secondNonce)
		response := serverVerdict(request, true, "")
		response.ApprovalNonce = firstNonce
		require.Error(t, am.HandleSudoApprovalResponse(response))
		response.ApprovalNonce = ""
		require.Error(t, am.HandleSudoApprovalResponse(response))
		response.ApprovalNonce = secondNonce
		require.NoError(t, am.HandleSudoApprovalResponse(response))
		assert.Contains(t, second.output(t), `"approved":true`)
	})
}

func TestSudoPostRetryReusesApprovalNonce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalBody: pendingBody(300), approvalStatuses: []int{http.StatusInternalServerError, http.StatusOK}}
		am := newHoldTestManager(t, server)
		client, _ := startPAMClient(t, am, holdTestRequest("4100", true))
		select {
		case line := <-client.lines:
			require.Contains(t, line, "approval_pending")
		case <-time.After(time.Minute):
			t.Fatal("no interim frame after POST retry")
		}
		posts := server.postsTo("/sudo-approval/")
		require.Len(t, posts, 2)
		require.Regexp(t, `^[0-9a-f]{32}$`, posts[0].body["approval_nonce"])
		assert.Equal(t, posts[0].body["approval_nonce"], posts[1].body["approval_nonce"])
		am.mu.Lock()
		req := am.findRequestLocked("4100")
		am.mu.Unlock()
		require.True(t, am.finalizeRequest(req, "Response timeout"))
		assert.Contains(t, client.output(t), `"approved":false`)
	})
}

func TestSudoPostNonceAcknowledgement(t *testing.T) {
	for _, mode := range []string{"echo", "absent", "different", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := &fakeAlpacon{approvalAnswer: func(body map[string]any) string {
					answer := map[string]any{"status": "mfa_required"}
					switch mode {
					case "echo":
						answer["approval_nonce"] = body["approval_nonce"]
					case "different":
						answer["approval_nonce"] = strings.Repeat("b", 32)
					case "malformed":
						answer["approval_nonce"] = 123
					}
					raw, err := json.Marshal(answer)
					require.NoError(t, err)
					return string(raw)
				}}
				am := newHoldTestManager(t, server)
				request := holdTestRequest("4100", false)
				client, _ := startPAMClient(t, am, request)
				synctest.Wait()
				verdict := serverVerdict(request, true, "")
				if mode == "echo" {
					require.ErrorContains(t, am.HandleSudoApprovalResponse(verdict), "missing approval nonce")
					verdict.ApprovalNonce = server.postsTo("/sudo-approval/")[0].body["approval_nonce"].(string)
				}
				require.NoError(t, am.HandleSudoApprovalResponse(verdict))
				assert.Contains(t, client.output(t), `"approved":true`)
			})
		})
	}
}

func TestSudoVerdictBeforePostAcknowledgement(t *testing.T) {
	for _, mode := range []string{"nonce=false", "nonce=true", "unbound"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := &fakeAlpacon{approvalAnswer: func(body map[string]any) string {
					answer := map[string]any{"status": "mfa_required"}
					if mode != "unbound" {
						answer["approval_nonce"] = body["approval_nonce"]
					}
					raw, err := json.Marshal(answer)
					require.NoError(t, err)
					return string(raw)
				}}
				am := newHoldTestManager(t, server)
				request := holdTestRequest("4100", false)
				server.onApproval = func() {
					verdict := serverVerdict(request, true, "")
					if mode == "nonce=true" {
						verdict.ApprovalNonce = server.postsTo("/sudo-approval/")[0].body["approval_nonce"].(string)
					}
					require.NoError(t, am.HandleSudoApprovalResponse(verdict))
				}
				client, _ := startPAMClient(t, am, request)
				if mode == "nonce=false" {
					synctest.Wait()
					am.mu.Lock()
					req := am.findRequestLocked(request.RequestID)
					am.mu.Unlock()
					require.NotNil(t, req, "parked nonce-less verdict must leave the bound attempt pending")
					assert.True(t, req.nonceBound)
					assert.Empty(t, req.early)
					assert.Empty(t, client.lines)
					verdict := serverVerdict(request, true, "")
					verdict.ApprovalNonce = req.Request.ApprovalNonce
					require.NoError(t, am.HandleSudoApprovalResponse(verdict))
				}
				assert.Contains(t, client.output(t), `"approved":true`)
			})
		})
	}
}

func TestSudoParkedVerdictNonceMustMatchAttempt(t *testing.T) {
	req := newSudoRequest(nil, SudoApprovalRequest{RequestID: "1", ApprovalNonce: strings.Repeat("a", 32)})
	req.posting = true
	req.early = []SudoApprovalResponse{{RequestID: "1", ApprovalNonce: strings.Repeat("b", 32), Approved: true}}
	session := &SessionInfo{Requests: map[string]*SudoRequest{"1": req}}
	am := &AuthManager{pidToSessionMap: map[int]*SessionInfo{1: session}}
	_, delivered := am.settlePost(req, nil, nil)
	assert.False(t, delivered)
	assert.Same(t, req, session.Requests["1"])
	assert.Empty(t, req.early)
}

func TestSudoEchoedErrorAnswerBindsThroughRetryExhaustion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeAlpacon{approvalAnswer: func(body map[string]any) string {
			b, err := json.Marshal(map[string]any{"status": "error", "approval_nonce": body["approval_nonce"]})
			require.NoError(t, err)
			return string(b)
		}}
		for range 100 {
			server.approvalStatuses = append(server.approvalStatuses, 500)
		}
		am := newHoldTestManager(t, server)
		request := holdTestRequest("4100", false)
		server.onApproval = func() {
			if len(server.postsTo("/sudo-approval/")) == 1 {
				require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(request, true, "")))
			}
		}
		client, _ := startPAMClient(t, am, request)
		select {
		case <-client.done:
		case <-time.After(time.Minute):
			t.Fatal("POST retries did not settle")
		}
		var delivered SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(client.output(t)), &delivered))
		assert.False(t, delivered.Approved, "an echoed error answer must bind before judging the parked nonce-less approval")
		posts := server.postsTo("/sudo-approval/")
		require.Greater(t, len(posts), 1)
		for _, post := range posts {
			assert.Equal(t, posts[0].body["approval_nonce"], post.body["approval_nonce"])
		}
	})
}

func TestSudoEchoedErrorAnswerStaysBoundAfterNonEchoingSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		answers := 0
		secondAnswer := make(chan struct{})
		server := &fakeAlpacon{approvalStatuses: []int{500, 200}, approvalAnswer: func(body map[string]any) string {
			answers++
			if answers > 1 {
				close(secondAnswer)
				return `{}`
			}
			b, err := json.Marshal(map[string]any{"status": "error", "approval_nonce": body["approval_nonce"]})
			require.NoError(t, err)
			return string(b)
		}}
		am := newHoldTestManager(t, server)
		request := holdTestRequest("4100", false)
		server.onApproval = func() {
			if len(server.postsTo("/sudo-approval/")) == 1 {
				require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(request, true, "")))
			}
		}
		client, _ := startPAMClient(t, am, request)
		select {
		case <-secondAnswer:
			synctest.Wait()
			am.mu.Lock()
			req := am.findRequestLocked(request.RequestID)
			require.NotNil(t, req)
			assert.True(t, req.nonceBound)
			assert.Empty(t, req.early)
			am.mu.Unlock()
			assert.Empty(t, client.lines)
			verdict := serverVerdict(request, true, "")
			verdict.ApprovalNonce = req.Request.ApprovalNonce
			require.NoError(t, am.HandleSudoApprovalResponse(verdict))
		case <-time.After(time.Minute):
			t.Fatal("POST retries did not settle")
		}
		var delivered SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(client.output(t)), &delivered))
		assert.True(t, delivered.Approved)
		posts := server.postsTo("/sudo-approval/")
		require.Greater(t, len(posts), 1)
		for _, post := range posts {
			assert.Equal(t, posts[0].body["approval_nonce"], post.body["approval_nonce"])
		}
	})
}

func TestSudoVerdictLoggingOmitsNonce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		previous, level, manager := log.Logger, zerolog.GlobalLevel(), authManager
		log.Logger = zerolog.New(&output)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		t.Cleanup(func() { log.Logger = previous; zerolog.SetGlobalLevel(level); authManager = manager })
		am := newHoldTestManager(t, &fakeAlpacon{approvalBody: `{}`})
		authManager = am
		request := holdTestRequest("4100", false)
		client, _ := startPAMClient(t, am, request)
		synctest.Wait()
		am.mu.Lock()
		req := am.findRequestLocked(request.RequestID)
		require.NotNil(t, req)
		nonce := req.Request.ApprovalNonce
		am.mu.Unlock()
		verdict := serverVerdict(request, true, "")
		verdict.Type = "sudo_approval_response"
		verdict.ApprovalNonce = nonce
		data, err := json.Marshal(verdict)
		require.NoError(t, err)
		wire, err := json.Marshal(ControlMessage{Query: "control", Data: data})
		require.NoError(t, err)
		control := &ControlClient{}
		control.HandleMessage(wire)
		assert.Contains(t, client.output(t), `"approved":true`)
		assert.NotContains(t, output.String(), nonce)
		output.Reset()
		control.HandleMessage(wire)
		assert.Contains(t, output.String(), "No pending sudo_approval request for response")
		assert.NotContains(t, output.String(), nonce)
	})
}
