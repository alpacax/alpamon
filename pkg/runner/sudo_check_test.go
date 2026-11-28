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
		{name: "delayed live session", check: true, delay: time.Hour, wantApproved: true},
		{name: "delayed ended session", check: true, end: true, delay: time.Hour},
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
				if tc.check {
					am.RemovePIDSessionMapping(holdTestPPID)
					retry, _ := startPAMClient(t, am, req)
					var repeated SudoApprovalResponse
					require.NoError(t, json.Unmarshal([]byte(retry.output(t)), &repeated))
					assert.False(t, repeated.Approved)
				}
			})
		})
	}
}

func TestCheckedSudoProcessIdentityAndCapacity(t *testing.T) {
	am := newTestAuthManager()
	lookup := func(int) (uint64, bool) { return 10, false }
	require.False(t, am.rememberCheckedSudoLocked(1, 0, lookup))
	for pid := 1; pid <= maxCheckedSudo; pid++ {
		require.True(t, am.rememberCheckedSudoLocked(pid, 10, lookup))
	}
	assert.False(t, am.rememberCheckedSudoLocked(maxCheckedSudo+1, 20, lookup))
	unreadable := func(int) (uint64, bool) { return 0, false }
	assert.False(t, am.rememberCheckedSudoLocked(maxCheckedSudo+1, 20, unreadable))
	for _, tc := range []struct {
		name    string
		pid     int
		current uint64
		absent  bool
	}{
		{"absent", 1, 0, true},
		{"reused", 2, 11, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := func(pid int) (uint64, bool) {
				if pid == tc.pid {
					return tc.current, tc.absent
				}
				return am.checkedSudo[pid], false
			}
			assert.True(t, am.rememberCheckedSudoLocked(maxCheckedSudo+tc.pid, 20, probe))
			assert.NotContains(t, am.checkedSudo, tc.pid)
			assert.Len(t, am.checkedSudo, maxCheckedSudo)
		})
	}
	assert.True(t, am.wasCheckedSudoLocked(3, 0))
	assert.True(t, am.wasCheckedSudoLocked(3, 10))
	assert.True(t, am.wasCheckedSudoLocked(3, 10))
	assert.False(t, am.wasCheckedSudoLocked(4, 20))
	assert.NotContains(t, am.checkedSudo, 4)
}
