package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/alpacax/alpamon/internal/protocol"
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

	if string(payload) != expected {
		t.Errorf("canonical payload mismatch\ngot:  %s\nwant: %s", string(payload), expected)
	}
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

	if string(payload) != expected {
		t.Errorf("canonical payload mismatch\ngot:  %s\nwant: %s", string(payload), expected)
	}
}

func TestVerifyCommand_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

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

	if err := VerifyCommand(cmd, serverID, pub); err != nil {
		t.Errorf("expected valid signature, got error: %v", err)
	}
}

func TestVerifyCommand_TamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

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

	err := VerifyCommand(cmd, serverID, pub)
	if err == nil {
		t.Error("expected verification failure for tampered command")
	}
}

func TestVerifyCommand_WrongServerID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

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

	err := VerifyCommand(cmd, "different-server", pub)
	if err == nil {
		t.Error("expected verification failure for wrong server ID")
	}
}

func TestVerifyCommand_EmptySignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	cmd := &protocol.Command{
		ID:    "cmd-123",
		Shell: "system",
		Line:  "whoami",
		User:  "root",
		Group: "root",
	}

	err := VerifyCommand(cmd, "server-456", pub)
	if err == nil {
		t.Error("expected error for empty signature")
	}
}

func TestVerifyCommand_InvalidBase64(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	cmd := &protocol.Command{
		ID:        "cmd-123",
		Shell:     "system",
		Line:      "whoami",
		User:      "root",
		Group:     "root",
		Signature: "not-valid-base64!!!",
	}

	err := VerifyCommand(cmd, "server-456", pub)
	if err == nil {
		t.Error("expected error for invalid base64 signature")
	}
}

func TestVerifyCommand_WrongSignatureSize(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	cmd := &protocol.Command{
		ID:        "cmd-123",
		Shell:     "system",
		Line:      "whoami",
		User:      "root",
		Group:     "root",
		Signature: base64.StdEncoding.EncodeToString([]byte("tooshort")),
	}

	err := VerifyCommand(cmd, "server-456", pub)
	if err == nil {
		t.Error("expected error for wrong signature size")
	}
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

	err := VerifyCommand(cmd, "server-456", nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}

func TestVerifyCommand_NilCommand(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	err := VerifyCommand(nil, "server-456", pub)
	if err == nil {
		t.Error("expected error for nil command")
	}
}

func TestBuildCanonicalPayload_NilCommand(t *testing.T) {
	payload := BuildCanonicalPayload(nil, "srv-1")
	if payload != nil {
		t.Errorf("expected nil payload for nil command, got %s", string(payload))
	}
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

	payload := BuildCanonicalPayload(cmd, "srv-1")

	// Payload must contain raw UTF-8 bytes, not \u2028/\u2029 escapes
	if bytes.Contains(payload, []byte(`\u2028`)) || bytes.Contains(payload, []byte(`\u2029`)) {
		t.Errorf("U+2028/U+2029 should not be escaped in canonical payload\ngot: %s", string(payload))
	}
	// Verify the raw bytes are present
	if !bytes.Contains(payload, []byte("\u2028")) || !bytes.Contains(payload, []byte("\u2029")) {
		t.Error("payload should contain raw U+2028/U+2029 bytes")
	}
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

	payload := BuildCanonicalPayload(cmd, "srv-1")

	// Must NOT contain raw U+2028/U+2029 bytes (those would mean corruption)
	if bytes.Contains(payload, []byte("\u2028")) || bytes.Contains(payload, []byte("\u2029")) {
		t.Errorf("literal \\u2028/\\u2029 text should not become raw bytes\ngot: %s", string(payload))
	}
	// JSON should contain the escaped form \\u2028/\\u2029
	if !bytes.Contains(payload, []byte(`\\u2028`)) || !bytes.Contains(payload, []byte(`\\u2029`)) {
		t.Errorf("literal \\u2028/\\u2029 should remain as \\\\u2028/\\\\u2029 in JSON\ngot: %s", string(payload))
	}
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

	if string(payload) != expected {
		t.Errorf("HTML chars should not be escaped\ngot:  %s\nwant: %s", string(payload), expected)
	}
}
