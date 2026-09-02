package runner

import (
	"errors"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/signing"
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

// enforcesSignature reports whether a command that fails verification must be
// refused rather than warned about and run.
//
// The fleet mode decides for every lane but one. A "file" command always
// enforces, because there the command line is a rendering and the structured
// payload decides what runs (ADR 0053): the signature is the only thing between
// a rewritten instruction and a digest that then verifies against the file the
// rewriter named. Verifying the entrypoint against an instruction nothing
// vouches for proves the requester's own claim back to them.
//
// The reason the general lane runs unenforced does not reach here. That reason
// is skew—older agents that cannot verify—and the server admits this lane only
// for an agent version that can, so there is no such agent to break.
func (wc *WebsocketClient) enforcesSignature(cmd *protocol.Command) bool {
	return wc.signingMode == "enforce" || cmd.Shell == "file"
}

// verifyCommandSignature checks the Ed25519 signature on a command.
// Internal commands bypass verification. In monitor mode, unsigned or
// invalid signatures log a warning but allow execution. In enforce mode—and on
// the file lane whatever the mode is, see enforcesSignature—they return an
// error which prevents ACK and execution.
func (wc *WebsocketClient) verifyCommandSignature(cmd *protocol.Command) error {
	// Internal commands bypass verification (no signature expected)
	if cmd.Shell == "internal" {
		return nil
	}

	// No signature: unsigned command
	if cmd.Signature == "" {
		if wc.enforcesSignature(cmd) {
			return newRejection(rejectReasonUnsigned,
				errors.New("missing signature on a command that requires one"))
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
		if wc.enforcesSignature(cmd) {
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

	// Commands without key_id use TTL-based cache via GetPublicKey(). During
	// key rotation the cached key may be stale but not yet expired, causing a
	// mismatch. Retry once with an unconditional refresh (env-scoped, no
	// relay-provided key_id) to pick up the rotated key immediately.
	if cmd.KeyID == "" && errors.Is(err, signing.ErrSignatureMismatch) {
		if refreshedKey, refreshErr := wc.keyManager.RefreshAndGet(); refreshErr == nil {
			if signing.VerifyCommand(cmd, wc.serverID, refreshedKey) == nil {
				log.Debug().Str("command_id", cmd.ID).
					Msg("Command signature verified after key refresh.")
				return nil
			}
		}
	}

	if wc.enforcesSignature(cmd) {
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
