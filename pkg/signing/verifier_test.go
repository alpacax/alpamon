package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
)

func TestBuildCanonicalPayload(t *testing.T) {
	cmd := &protocol.Command{
		ID:         "test-uuid",
		Shell:      "system",
		Line:       "echo hello",
		User:       "root",
		Group:      "alpacon",
		AnalyzedAt: "2026-01-01T00:00:00+00:00",
	}

	payload := BuildCanonicalPayload(cmd, "server-uuid")

	// Must match Python's json.dumps(sort_keys=True, separators=(',', ':'))
	expected := `{"command_id":"test-uuid","groupname":"alpacon","line":"echo hello","server_id":"server-uuid","shell":"system","timestamp":"2026-01-01T00:00:00+00:00","username":"root"}`

	assert.Equal(t, expected, string(payload))
}

func TestBuildCanonicalPayload_EmptyAnalyzedAt(t *testing.T) {
	cmd := &protocol.Command{
		ID:    "cmd-1",
		Shell: "system",
		Line:  "ls",
		User:  "deploy",
		Group: "deploy",
	}

	payload := BuildCanonicalPayload(cmd, "srv-1")
	expected := `{"command_id":"cmd-1","groupname":"deploy","line":"ls","server_id":"srv-1","shell":"system","timestamp":"","username":"deploy"}`

	assert.Equal(t, expected, string(payload))
}

func TestVerifyCommand_Valid(t *testing.T) {
	pub, priv := newTestKey(t)

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
	}
	serverID := "server-456"

	payload := BuildCanonicalPayload(cmd, serverID)
	sig := ed25519.Sign(priv, payload)
	cmd.Signature = base64.StdEncoding.EncodeToString(sig)

	assert.NoError(t, VerifyCommand(cmd, serverID, pub))
}

func TestVerifyCommand_TamperedPayload(t *testing.T) {
	pub, priv := newTestKey(t)

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
	}
	serverID := "server-456"

	payload := BuildCanonicalPayload(cmd, serverID)
	sig := ed25519.Sign(priv, payload)
	cmd.Signature = base64.StdEncoding.EncodeToString(sig)

	// Tamper with the command
	cmd.Line = "rm -rf /"

	assert.ErrorIs(t, VerifyCommand(cmd, serverID, pub), ErrSignatureMismatch)
}

func TestVerifyCommand_WrongServerID(t *testing.T) {
	pub, priv := newTestKey(t)

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
	}

	payload := BuildCanonicalPayload(cmd, "server-456")
	sig := ed25519.Sign(priv, payload)
	cmd.Signature = base64.StdEncoding.EncodeToString(sig)

	assert.ErrorIs(t, VerifyCommand(cmd, "different-server", pub), ErrSignatureMismatch)
}

func TestVerifyCommand_EmptySignature(t *testing.T) {
	pub, _ := newTestKey(t)

	cmd := &protocol.Command{
		ID:    "cmd-123",
		Shell: "system",
		Line:  "whoami",
		User:  "root",
		Group: "root",
	}

	assert.ErrorContains(t, VerifyCommand(cmd, "server-456", pub), "empty signature")
}

func TestVerifyCommand_InvalidBase64(t *testing.T) {
	pub, _ := newTestKey(t)

	cmd := &protocol.Command{
		ID:        "cmd-123",
		Shell:     "system",
		Line:      "whoami",
		User:      "root",
		Group:     "root",
		Signature: "not-valid-base64!!!",
	}

	assert.ErrorContains(t, VerifyCommand(cmd, "server-456", pub), "invalid signature encoding")
}

func TestVerifyCommand_WrongSignatureSize(t *testing.T) {
	pub, _ := newTestKey(t)

	cmd := &protocol.Command{
		ID:        "cmd-123",
		Shell:     "system",
		Line:      "whoami",
		User:      "root",
		Group:     "root",
		Signature: base64.StdEncoding.EncodeToString([]byte("tooshort")),
	}

	assert.ErrorContains(t, VerifyCommand(cmd, "server-456", pub), "invalid signature size")
}

func TestVerifyCommand_NilPublicKey(t *testing.T) {
	cmd := &protocol.Command{
		ID:        "cmd-123",
		Shell:     "system",
		Line:      "whoami",
		User:      "root",
		Group:     "root",
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}

	assert.ErrorContains(t, VerifyCommand(cmd, "server-456", nil), "invalid public key size")
}

func TestVerifyCommand_NilCommand(t *testing.T) {
	pub, _ := newTestKey(t)

	assert.ErrorContains(t, VerifyCommand(nil, "server-456", pub), "nil command")
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

func TestBuildCanonicalPayload_HTMLChars(t *testing.T) {
	// Verify that <, >, & are NOT escaped (matching Python's json.dumps behavior)
	cmd := &protocol.Command{
		ID:         "cmd-1",
		Shell:      "system",
		Line:       "echo '<h1>test</h1>' & cat /etc/passwd",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-01-01T00:00:00+00:00",
	}

	payload := BuildCanonicalPayload(cmd, "srv-1")
	expected := `{"command_id":"cmd-1","groupname":"root","line":"echo '<h1>test</h1>' & cat /etc/passwd","server_id":"srv-1","shell":"system","timestamp":"2026-01-01T00:00:00+00:00","username":"root"}`

	assert.Equal(t, expected, string(payload))
}
