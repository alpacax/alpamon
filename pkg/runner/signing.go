package runner

import (
	"errors"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/signing"
	"github.com/rs/zerolog/log"
)

// Rejection reasons sent to the server via the reject endpoint.
// These are fixed strings to avoid leaking internal details (AI server URLs,
// status codes, key IDs) into server-side records visible to console users.
const (
	rejectReasonUnsigned          = "unsigned_command"
	rejectReasonKeyUnavailable    = "key_unavailable"
	rejectReasonInvalidSignature  = "invalid_signature"
	rejectReasonSignatureMismatch = "signature_mismatch"
)

// rejectionError pairs a user-facing reason (sent to server) with an internal
// error (logged locally). This avoids leaking implementation details into the
// reject payload while preserving full diagnostics in logs.
type rejectionError struct {
	reason string // fixed string for the server
	err    error  // detailed error for local logging
}

func (r *rejectionError) Error() string { return r.reason }
func (r *rejectionError) Unwrap() error { return r.err }

func newRejection(reason string, err error) *rejectionError {
	return &rejectionError{reason: reason, err: err}
}

// verifyCommandSignature checks the Ed25519 signature on a command.
// Internal commands bypass verification. In monitor mode, unsigned or
// invalid signatures log a warning but allow execution. In enforce mode,
// they return an error which prevents ACK and execution.
func (wc *WebsocketClient) verifyCommandSignature(cmd *protocol.Command) error {
	// Internal commands bypass verification (no signature expected)
	if cmd.Shell == "internal" {
		return nil
	}

	// No signature: unsigned command
	if cmd.Signature == "" {
		if wc.signingMode == "enforce" {
			return newRejection(rejectReasonUnsigned,
				errors.New("missing signature in enforce mode"))
		}
		log.Warn().Str("command_id", cmd.ID).Msg("Command has no signature (unsigned).")
		return nil
	}

	// Resolve public key using key_id from the command
	var pubKey []byte
	var err error

	if cmd.KeyID != "" {
		pubKey, err = wc.keyManager.GetPublicKeyForKID(cmd.KeyID)
	} else {
		pubKey, err = wc.keyManager.GetPublicKey()
	}

	if err != nil {
		if wc.signingMode == "enforce" {
			return newRejection(rejectReasonKeyUnavailable,
				fmt.Errorf("public key unavailable: %w", err))
		}
		log.Warn().Err(err).Str("command_id", cmd.ID).
			Msg("Public key unavailable, executing without verification.")
		return nil
	}

	// Verify signature
	err = signing.VerifyCommand(cmd, wc.serverID, pubKey)
	if err == nil {
		log.Debug().Str("command_id", cmd.ID).Msg("Command signature verified.")
		return nil
	}

	if wc.signingMode == "enforce" {
		reason := rejectReasonInvalidSignature
		if errors.Is(err, signing.ErrSignatureMismatch) {
			reason = rejectReasonSignatureMismatch
		}
		return newRejection(reason, err)
	}
	log.Warn().Err(err).Str("command_id", cmd.ID).
		Msg("Signature verification failed, executing in monitor mode.")
	return nil
}

// rejectCommand reports a rejected command to alpacon-server.
func (wc *WebsocketClient) rejectCommand(commandID string, reason string) {
	payload := map[string]string{
		"reason": reason,
	}
	scheduler.Rqueue.Post(
		fmt.Sprintf(eventCommandRejectURL, commandID),
		payload,
		10,
		time.Time{},
	)
}
