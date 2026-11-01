package runner

import (
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecondVerdictAfterAnsweredRequest(t *testing.T) {
	for _, parked := range []bool{false, true} {
		for _, failedWrite := range []bool{false, true} {
			for _, identical := range []bool{false, true} {
				name := "direct"
				if parked {
					name = "parked held"
				}
				if failedWrite {
					name += "/failed write"
				} else {
					name += "/successful write"
				}
				if identical {
					name += "/identical successor"
				} else {
					name += "/different command"
				}
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						server := &fakeAlpacon{approvalBody: `{"status":"mfa_required"}`}
						am := newHoldTestManager(t, server)
						old := holdTestRequest("203", parked)
						verdict := serverVerdict(old, true, "")
						var release chan struct{}
						if parked {
							release = make(chan struct{})
							server.approvalBody = pendingBody(300)
							server.onApproval = func() { <-release; require.NoError(t, am.HandleSudoApprovalResponse(verdict)) }
						}
						pc, rec := startPAMClient(t, am, old)
						synctest.Wait()
						if failedWrite {
							require.NoError(t, rec.Conn.Close())
						}
						if parked {
							close(release)
							synctest.Wait()
						} else {
							err := am.HandleSudoApprovalResponse(verdict)
							if failedWrite {
								require.Error(t, err)
							} else {
								require.NoError(t, err)
							}
						}
						if !failedWrite {
							require.Equal(t, marshalResponse(t, verdict), pc.output(t))
						} else {
							pc.output(t)
							assert.Equal(t, 1, rec.writeCount())
						}
						// The next post must not park a verdict or hold the successor.
						server.onApproval = nil
						server.approvalBody = `{"status":"mfa_required"}`
						current := old
						if !identical {
							current.Command = "different-placeholder"
						}
						pc2, rec2 := startPAMClient(t, am, current)
						synctest.Wait()
						err := am.HandleSudoApprovalResponse(verdict)
						if identical {
							require.NoError(t, err)
							assert.Equal(t, marshalResponse(t, verdict), pc2.output(t))
						} else {
							assert.Error(t, err)
							assert.Zero(t, rec2.writeCount(), "second verdict reached the different-command successor")
							am.RemovePIDSessionMapping(holdTestPPID)
							pc2.output(t)
						}
					})
				})
			}
		}
	}
}

func TestSudoRequestIDMustEqualDecimalPID(t *testing.T) {
	for _, id := range []string{"204", "0203", "arbitrary", ""} {
		t.Run(id, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := &fakeAlpacon{approvalBody: `{"status":"mfa_required"}`}
				am := newHoldTestManager(t, server)
				req := holdTestRequest("203", false)
				req.RequestID = id
				pc, _ := startPAMClient(t, am, req)
				assert.Contains(t, pc.output(t), "Invalid sudo_approval_request")
				assert.Empty(t, server.recorded())
				am.mu.RLock()
				assert.Empty(t, am.pidToSessionMap[holdTestPPID].Requests)
				am.mu.RUnlock()
			})
		})
	}
}
