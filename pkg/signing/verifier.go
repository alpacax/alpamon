package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/alpacax/alpamon/internal/protocol"
)

// signingPayload defines the canonical payload that the AI server signs.
// Struct fields are ordered alphabetically by JSON tag to match Python's
// json.dumps(sort_keys=True, separators=(',', ':')).
type signingPayload struct {
	CommandID string `json:"command_id"`
	GroupName string `json:"groupname"`
	Line      string `json:"line"`
	ServerID  string `json:"server_id"`
	Shell     string `json:"shell"`
	Timestamp string `json:"timestamp"`
	Username  string `json:"username"`
}

// BuildCanonicalPayload constructs the signing payload that must match
// what the AI server signed. The output is deterministic canonical JSON.
// Uses json.Encoder with SetEscapeHTML(false) and unescapes U+2028/U+2029
// to match Python's json.dumps(ensure_ascii=False) behavior exactly.
// Go's encoding/json escapes U+2028/U+2029 even with SetEscapeHTML(false),
// but Python emits them as raw UTF-8.
func BuildCanonicalPayload(cmd *protocol.Command, serverID string) []byte {
	if cmd == nil {
		return nil
	}
	p := signingPayload{
		CommandID: cmd.ID,
		GroupName: cmd.Group,
		Line:      cmd.Line,
		ServerID:  serverID,
		Shell:     cmd.Shell,
		Timestamp: cmd.AnalyzedAt,
		Username:  cmd.User,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(p)
	// Encoder.Encode appends a newline; trim it for canonical form
	result := bytes.TrimRight(buf.Bytes(), "\n")
	// Unescape U+2028/U+2029 that Go escapes but Python does not.
	// Only replace \u2028/\u2029 when not preceded by a backslash
	// (i.e., skip \\u2028 which represents a literal backslash in JSON).
	result = unescapeLineSeparators(result)
	return result
}

// unescapeLineSeparators replaces JSON-escaped \u2028 and \u2029 with raw
// UTF-8 bytes, but only when the leading backslash is not itself escaped.
// Escaping is determined by counting consecutive preceding backslashes:
// odd count means the backslash is escaped (part of \\), even means it
// introduces a real JSON escape sequence.
func unescapeLineSeparators(data []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == '\\' && i+5 < len(data) && data[i+1] == 'u' &&
			(string(data[i+2:i+6]) == "2028" || string(data[i+2:i+6]) == "2029") {
			// Count consecutive preceding backslashes
			backslashCount := 0
			for j := i - 1; j >= 0 && data[j] == '\\'; j-- {
				backslashCount++
			}
			if backslashCount%2 == 1 {
				// Odd preceding backslashes: this backslash is escaped, not a JSON escape
				buf.WriteByte(data[i])
				continue
			}
			if string(data[i+2:i+6]) == "2028" {
				buf.WriteString("\u2028")
			} else {
				buf.WriteString("\u2029")
			}
			i += 5 // skip past uXXXX
		} else {
			buf.WriteByte(data[i])
		}
	}
	return buf.Bytes()
}

// VerifyCommand verifies the Ed25519 signature on a command.
// The caller is responsible for resolving the public key, typically
// by calling KeyManager.GetPublicKeyForKID(cmd.KeyID).
func VerifyCommand(cmd *protocol.Command, serverID string, publicKey ed25519.PublicKey) error {
	if cmd == nil {
		return errors.New("nil command")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	if cmd.Signature == "" {
		return errors.New("empty signature")
	}

	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	payload := BuildCanonicalPayload(cmd, serverID)

	if !ed25519.Verify(publicKey, payload, sig) {
		return errors.New("signature verification failed")
	}

	return nil
}
