package signing

import (
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
	data, _ := json.Marshal(p)
	return data
}

// VerifyCommand verifies the Ed25519 signature on a command.
func VerifyCommand(cmd *protocol.Command, serverID string, publicKey ed25519.PublicKey) error {
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
