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
// Uses json.Encoder with SetEscapeHTML(false) to match Python's json.dumps
// behavior, which does not escape <, >, or & characters.
func BuildCanonicalPayload(cmd *protocol.Command, serverID string) []byte {
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
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// VerifyCommand verifies the Ed25519 signature on a command.
func VerifyCommand(cmd *protocol.Command, serverID string, publicKey ed25519.PublicKey) error {
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
