package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMessage_Command(t *testing.T) {
	raw := `{
		"query": "command",
		"command": {
			"id": "test-123",
			"shell": "internal",
			"line": "ping",
			"user": "root",
			"group": "root",
			"env": {"FOO": "bar"},
			"data": "{\"session_id\": \"sess-456\"}"
		}
	}`

	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, MessageTypeCommand, msg.Query)
	require.NotNil(t, msg.Command)
	assert.Equal(t, "test-123", msg.Command.ID)
	assert.Equal(t, "internal", msg.Command.Shell)
	assert.Equal(t, "ping", msg.Command.Line)
	assert.Equal(t, "root", msg.Command.User)
	assert.Equal(t, "bar", msg.Command.Env["FOO"])
}

func TestParseMessage_Quit(t *testing.T) {
	raw := `{"query": "quit", "reason": "server shutdown"}`

	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, MessageTypeQuit, msg.Query)
	assert.Equal(t, "server shutdown", msg.Reason)
}

func TestParseMessage_Reconnect(t *testing.T) {
	raw := `{"query": "reconnect", "reason": "server restart"}`

	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, MessageTypeReconnect, msg.Query)
	assert.Equal(t, "server restart", msg.Reason)
}

func TestParseMessage_Invalid(t *testing.T) {
	raw := `invalid json`

	msg, err := ParseMessage([]byte(raw))
	assert.Error(t, err)
	assert.Nil(t, msg)
}

func TestCommand_ParseCommandData(t *testing.T) {
	cmd := &Command{
		ID:    "test-123",
		Shell: "internal",
		Line:  "adduser",
		Data:  `{"username": "testuser", "uid": 1000, "gid": 1000}`,
	}

	data, err := cmd.ParseCommandData()
	require.NoError(t, err)
	assert.Equal(t, "testuser", data.Username)
	assert.Equal(t, uint64(1000), data.UID)
	assert.Equal(t, uint64(1000), data.GID)
}

func TestCommand_ParseCommandData_Empty(t *testing.T) {
	cmd := &Command{
		ID:   "test-123",
		Data: "",
	}

	data, err := cmd.ParseCommandData()
	require.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, "", data.Username)
}

func TestCommand_ParseCommandData_Invalid(t *testing.T) {
	cmd := &Command{
		ID:   "test-123",
		Data: "invalid json",
	}

	data, err := cmd.ParseCommandData()
	assert.Error(t, err)
	assert.Nil(t, data)
}

func TestNewCommandResponse(t *testing.T) {
	resp := NewCommandResponse(true, "success output", 1.5)

	assert.True(t, resp.Success)
	assert.Equal(t, "success output", resp.Result)
	assert.Equal(t, 1.5, resp.ElapsedTime)
}

func TestNewPingResponse(t *testing.T) {
	resp := NewPingResponse()

	assert.Equal(t, "ping", resp.Query)
	assert.False(t, resp.Timestamp.IsZero())
}

func TestCommandResponse_JSON(t *testing.T) {
	resp := NewCommandResponse(true, "done", 2.5)

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded CommandResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Success, decoded.Success)
	assert.Equal(t, resp.Result, decoded.Result)
	assert.Equal(t, resp.ElapsedTime, decoded.ElapsedTime)
}
