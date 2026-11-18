package protocol

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWorkSessionID = "11111111-1111-4111-8111-111111111111"

func parseCommandMessage(t *testing.T, raw string) (*Command, *CommandData) {
	t.Helper()
	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	require.NotNil(t, msg.Command)
	data, err := msg.Command.ParseCommandData()
	require.NoError(t, err)
	return msg.Command, data
}

func TestWorkSessionFromCommandExecute(t *testing.T) {
	cmd, data := parseCommandMessage(t, `{"query":"command","command":{"id":"c1","shell":"system","line":"ls",
		"work_session_id":"`+testWorkSessionID+`","work_session_revision":"3",
		"work_session_expires_at":"2026-11-18T10:00:00Z"}}`)

	ws, err := cmd.WorkSession(data)
	require.NoError(t, err)
	assert.Equal(t, testWorkSessionID, ws.ID)
	assert.Equal(t, uint64(3), ws.Revision)
	assert.Equal(t, time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC), ws.ExpiresAt)
}

func TestWorkSessionRevisionAcceptsJSONNumber(t *testing.T) {
	cmd, data := parseCommandMessage(t, `{"query":"command","command":{"id":"c1","shell":"system","line":"ls",
		"work_session_id":"`+testWorkSessionID+`","work_session_revision":7,
		"work_session_expires_at":"2026-11-18T10:00:00Z"}}`)

	ws, err := cmd.WorkSession(data)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), ws.Revision)
}

func TestWorkSessionFromTerminalOpenData(t *testing.T) {
	inner, err := json.Marshal(map[string]any{
		"session_id":              "websh-1",
		"work_session_id":         testWorkSessionID,
		"work_session_revision":   "2",
		"work_session_expires_at": "2026-11-18T10:00:00Z",
	})
	require.NoError(t, err)
	outer, err := json.Marshal(map[string]any{
		"query":   "command",
		"command": map[string]any{"id": "c2", "shell": "internal", "line": "openpty", "data": string(inner)},
	})
	require.NoError(t, err)
	cmd, data := parseCommandMessage(t, string(outer))

	ws, err := cmd.WorkSession(data)
	require.NoError(t, err)
	assert.Equal(t, testWorkSessionID, ws.ID)
	assert.Equal(t, uint64(2), ws.Revision)
	assert.Equal(t, "websh-1", data.SessionID, "the terminal session_id is not reused for the work session")
}

func TestWorkSessionAbsentMeansSessionLess(t *testing.T) {
	cmd, data := parseCommandMessage(t, `{"query":"command","command":{"id":"c1","shell":"system","line":"ls"}}`)

	ws, err := cmd.WorkSession(data)
	require.NoError(t, err)
	assert.Empty(t, ws.ID)
}

func TestWorkSessionRejectsDisagreeingAttribution(t *testing.T) {
	cmd := &Command{
		ID:                   "c1",
		WorkSessionID:        testWorkSessionID,
		WorkSessionRevision:  1,
		WorkSessionExpiresAt: "2026-11-18T10:00:00Z",
	}
	data := &CommandData{
		WorkSessionID:        "22222222-2222-4222-8222-222222222222",
		WorkSessionRevision:  1,
		WorkSessionExpiresAt: "2026-11-18T10:00:00Z",
	}

	_, err := cmd.WorkSession(data)
	assert.ErrorContains(t, err, "disagree")
}

func TestWorkSessionRejectsMalformedAttribution(t *testing.T) {
	cases := map[string]*Command{
		"not a uuid":     {WorkSessionID: "../servers", WorkSessionExpiresAt: "2026-11-18T10:00:00Z"},
		"missing expiry": {WorkSessionID: testWorkSessionID},
		"bad expiry":     {WorkSessionID: testWorkSessionID, WorkSessionExpiresAt: "tomorrow"},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := cmd.WorkSession(&CommandData{})
			assert.Error(t, err)
		})
	}
}

func TestUint64StringRejectsNegativeAndFraction(t *testing.T) {
	for _, raw := range []string{`-1`, `"-1"`, `1.5`, `"x"`} {
		var v Uint64String
		assert.Error(t, json.Unmarshal([]byte(raw), &v), raw)
	}
}
