package runner

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckedSudoApproval(t *testing.T) {
	for _, tc := range []struct {
		name         string
		check, end   bool
		delay        time.Duration
		wantApproved bool
	}{
		{name: "session ended", check: true, end: true},
		{name: "session live", check: true, wantApproved: true},
		{name: "no prior check", end: true, wantApproved: true},
		{name: "before expiry", check: true, end: true, delay: 120*time.Second - time.Nanosecond},
		{name: "expired", check: true, end: true, delay: 120 * time.Second, wantApproved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := &fakeAlpacon{approvalBody: "{}"}
				am := newHoldTestManager(t, server)
				am.UpdateBlockLocalSudo(false)
				req := holdTestRequest(strconv.Itoa(os.Getpid()), false)
				if tc.check {
					req.Type = "check_user"
					client, _ := startPAMClient(t, am, req)
					var classification map[string]any
					require.NoError(t, json.Unmarshal([]byte(client.output(t)), &classification))
					require.Equal(t, true, classification["is_alpacon_user"])
					assert.NotContains(t, classification, "unmatched_session")
				}
				if tc.end {
					am.RemovePIDSessionMapping(holdTestPPID)
				}
				time.Sleep(tc.delay)
				req.Type = "sudo_approval"
				client, _ := startPAMClient(t, am, req)
				synctest.Wait()
				posts := server.postsTo("/sudo-approval/")
				if tc.end {
					assert.Empty(t, posts)
				} else {
					require.Len(t, posts, 1)
					assert.Equal(t, "/api/websh/sessions/"+holdTestSession+"/sudo-approval/", posts[0].path)
					require.NoError(t, am.HandleSudoApprovalResponse(serverVerdict(req, true, "")))
				}
				var result SudoApprovalResponse
				require.NoError(t, json.Unmarshal([]byte(client.output(t)), &result))
				assert.Equal(t, tc.wantApproved, result.Approved)
				assert.Empty(t, am.checkedSudo)
			})
		})
	}
}

func TestCheckedSudoProcessIdentityAndCapacity(t *testing.T) {
	am := newTestAuthManager()
	now := time.Now()
	require.False(t, am.rememberCheckedSudoLocked(1, 0, now))
	for pid := 1; pid <= maxCheckedSudo; pid++ {
		require.True(t, am.rememberCheckedSudoLocked(pid, 10, now))
	}
	assert.False(t, am.rememberCheckedSudoLocked(maxCheckedSudo+1, 20, now))
	assert.False(t, am.consumeCheckedSudoLocked(1, 20, now))
	assert.True(t, am.consumeCheckedSudoLocked(1, 0, now))
	assert.True(t, am.consumeCheckedSudoLocked(1, 10, now))
	assert.False(t, am.consumeCheckedSudoLocked(1, 10, now))
	require.True(t, am.rememberCheckedSudoLocked(1, 20, now))
	assert.True(t, am.rememberCheckedSudoLocked(maxCheckedSudo+1, 20, now.Add(sudoCheckTTL)))
	assert.Len(t, am.checkedSudo, 1)
}
