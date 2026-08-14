package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
)

func TestBuildCanonicalPayload(t *testing.T) {
	tests := []struct {
		name     string
		cmd      *protocol.Command
		serverID string
		// Must match Python's json.dumps(sort_keys=True, separators=(',', ':'))
		want string
	}{
		{
			name: "all fields set",
			cmd: &protocol.Command{
				ID:         "test-uuid",
				Shell:      "system",
				Line:       "echo hello",
				User:       "root",
				Group:      "alpacon",
				AnalyzedAt: "2026-01-01T00:00:00+00:00",
			},
			serverID: "server-uuid",
			want:     `{"command_id":"test-uuid","groupname":"alpacon","line":"echo hello","server_id":"server-uuid","shell":"system","timestamp":"2026-01-01T00:00:00+00:00","username":"root"}`,
		},
		{
			name: "empty analyzed_at",
			cmd: &protocol.Command{
				ID:    "cmd-1",
				Shell: "system",
				Line:  "ls",
				User:  "deploy",
				Group: "deploy",
			},
			serverID: "srv-1",
			want:     `{"command_id":"cmd-1","groupname":"deploy","line":"ls","server_id":"srv-1","shell":"system","timestamp":"","username":"deploy"}`,
		},
		{
			// <, > and & must not be escaped either, matching json.dumps
			name: "html characters",
			cmd: &protocol.Command{
				ID:         "cmd-1",
				Shell:      "system",
				Line:       "echo '<h1>test</h1>' & cat /etc/passwd",
				User:       "root",
				Group:      "root",
				AnalyzedAt: "2026-01-01T00:00:00+00:00",
			},
			serverID: "srv-1",
			want:     `{"command_id":"cmd-1","groupname":"root","line":"echo '<h1>test</h1>' & cat /etc/passwd","server_id":"srv-1","shell":"system","timestamp":"2026-01-01T00:00:00+00:00","username":"root"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(BuildCanonicalPayload(tt.cmd, tt.serverID)))
		})
	}
}

func TestBuildCanonicalPayload_NilCommand(t *testing.T) {
	assert.Nil(t, BuildCanonicalPayload(nil, "srv-1"))
}

func TestBuildCanonicalPayload_LineSeparators(t *testing.T) {
	// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) must NOT be
	// escaped, matching Python's json.dumps(ensure_ascii=False) behavior.
	// Go's encoding/json escapes these even with SetEscapeHTML(false).
	cmd := &protocol.Command{
		ID:         "cmd-1",
		Shell:      "system",
		Line:       "echo hello\u2028world\u2029end",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-01-01T00:00:00+00:00",
	}

	payload := string(BuildCanonicalPayload(cmd, "srv-1"))

	// Payload must contain raw UTF-8 bytes, not \u2028/\u2029 escapes
	assert.NotContains(t, payload, `\u2028`)
	assert.NotContains(t, payload, `\u2029`)
	// Verify the raw bytes are present
	assert.Contains(t, payload, "\u2028")
	assert.Contains(t, payload, "\u2029")
}

func TestBuildCanonicalPayload_LiteralBackslashU2028(t *testing.T) {
	// Verify that literal "\u2028"/"\u2029" text in user input is NOT
	// corrupted by the U+2028/U+2029 unescaping post-processing.
	cmd := &protocol.Command{
		ID:         "cmd-2",
		Shell:      "system",
		Line:       `echo hello\u2028and\u2029end`,
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-01-01T00:00:00+00:00",
	}

	payload := string(BuildCanonicalPayload(cmd, "srv-1"))

	// Must NOT contain raw U+2028/U+2029 bytes (those would mean corruption)
	assert.NotContains(t, payload, "\u2028")
	assert.NotContains(t, payload, "\u2029")
	// JSON should contain the escaped form \\u2028/\\u2029
	assert.Contains(t, payload, `\\u2028`)
	assert.Contains(t, payload, `\\u2029`)
}

func TestVerifyCommand_Valid(t *testing.T) {
	pub, priv := newTestKey(t)

	assert.NoError(t, VerifyCommand(signedCommand(t, priv, testServerID), testServerID, pub))
}

func TestVerifyCommand_TamperedPayload(t *testing.T) {
	pub, priv := newTestKey(t)

	cmd := signedCommand(t, priv, testServerID)
	cmd.Line = "rm -rf /"

	assert.ErrorIs(t, VerifyCommand(cmd, testServerID, pub), ErrSignatureMismatch)
}

func TestVerifyCommand_WrongServerID(t *testing.T) {
	pub, priv := newTestKey(t)

	cmd := signedCommand(t, priv, testServerID)

	assert.ErrorIs(t, VerifyCommand(cmd, "different-server", pub), ErrSignatureMismatch)
}

func TestVerifyCommand_Errors(t *testing.T) {
	pub, _ := newTestKey(t)

	tests := []struct {
		name string
		cmd  *protocol.Command
		key  ed25519.PublicKey
		want string
	}{
		{"empty signature", testCommand(""), pub, "empty signature"},
		{"invalid base64", testCommand("not-valid-base64!!!"), pub, "invalid signature encoding"},
		{"wrong signature size", testCommand(base64.StdEncoding.EncodeToString([]byte("tooshort"))), pub, "invalid signature size"},
		{"nil public key", testCommand(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))), nil, "invalid public key size"},
		{"nil command", nil, pub, "nil command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, VerifyCommand(tt.cmd, testServerID, tt.key), tt.want)
		})
	}
}
