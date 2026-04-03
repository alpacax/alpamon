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

// verifyCommandSignature checks the Ed25519 signature on a command.
// Internal commands bypass verification. In monitor mode, unsigned or
// invalid signatures log a warning but allow execution. In enforce mode,
// they return an error which prevents ACK and execution.
func (wc *WebsocketClient) verifyCommandSignature(cmd *protocol.Command) error {
	// Internal commands bypass verification (no signature expected)
	if cmd.Shell == "internal" {
		return nil
	}

	// Signing not configured: skip verification
	if wc.keyManager == nil {
		return nil
	}

	// No signature: unsigned command
	if cmd.Signature == "" {
		if wc.signingMode == "enforce" {
			return errors.New("missing signature in enforce mode")
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
			return fmt.Errorf("public key unavailable: %w", err)
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

	// Verification failed: try key refresh once (handles key rotation)
	log.Debug().Err(err).Str("command_id", cmd.ID).
		Msg("Signature verification failed, refreshing key.")

	retryErr := wc.retryVerificationAfterRefresh(cmd, err)
	if retryErr == nil {
		log.Debug().Str("command_id", cmd.ID).Msg("Command signature verified after key refresh.")
		return nil
	}

	if wc.signingMode == "enforce" {
		return retryErr
	}
	log.Warn().Err(retryErr).Str("command_id", cmd.ID).
		Msg("Signature verification failed, executing in monitor mode.")
	return nil
}

// retryVerificationAfterRefresh force-refreshes the public key and retries
// signature verification. ForceRefresh fetches unconditionally (unlike Refresh
// which is a no-op when the cached key hasn't expired), ensuring a rotated key
// is actually fetched.
func (wc *WebsocketClient) retryVerificationAfterRefresh(cmd *protocol.Command, originalErr error) error {
	if refreshErr := wc.keyManager.ForceRefresh(); refreshErr != nil {
		log.Warn().Err(refreshErr).Msg("Key refresh failed.")
		return fmt.Errorf("signature verification failed and key refresh failed: %w",
			errors.Join(originalErr, refreshErr))
	}

	var pubKey []byte
	var err error
	if cmd.KeyID != "" {
		pubKey, err = wc.keyManager.GetPublicKeyForKID(cmd.KeyID)
	} else {
		pubKey, err = wc.keyManager.GetPublicKey()
	}
	if err != nil {
		return fmt.Errorf("public key unavailable after refresh: %w", err)
	}

	if retryErr := signing.VerifyCommand(cmd, wc.serverID, pubKey); retryErr != nil {
		return fmt.Errorf("signature verification failed after key refresh: %w", retryErr)
	}

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
