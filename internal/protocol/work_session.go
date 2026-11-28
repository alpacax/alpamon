package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Uint64String is a protobuf uint64 in its JSON mapping: a decimal string.
// A bare JSON number is accepted as well, since not every sender quotes it.
type Uint64String uint64

func (v *Uint64String) UnmarshalJSON(raw []byte) error {
	text := string(bytes.TrimSpace(raw))
	if text == "null" {
		return nil
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid uint64 %q", text)
	}
	*v = Uint64String(n)
	return nil
}

func (v Uint64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}

// WorkSession is the Work Session attribution of one command or terminal
// open. An empty ID means genuinely session-less work.
type WorkSession struct {
	ID       string
	Revision uint64
	// ExpiresAt is zero for a session without an expiry.
	ExpiresAt time.Time
}

// WorkSession resolves attribution from the command and terminal data.
// Each attributed envelope requires an ID; two attributed envelopes must agree.
func (c *Command) WorkSession(data *CommandData) (WorkSession, error) {
	fromCommand := workSessionFields{c.WorkSessionID, c.WorkSessionRevision, c.WorkSessionExpiresAt}
	var fromData workSessionFields
	if data != nil {
		fromData = workSessionFields{data.WorkSessionID, data.WorkSessionRevision, data.WorkSessionExpiresAt}
	}
	for _, fields := range []workSessionFields{fromCommand, fromData} {
		if fields.id == "" && (fields.revision != 0 || fields.expiresAt != "") {
			return WorkSession{}, errors.New("work session attribution requires a work session ID")
		}
	}

	fields := fromCommand
	switch {
	case fromCommand.id == "" && fromData.id == "":
		return WorkSession{}, nil
	case fromCommand.id == "":
		fields = fromData
	case fromData.id != "" && fromData != fromCommand:
		return WorkSession{}, errors.New("command and data disagree on the work session")
	}
	return fields.parse()
}

type workSessionFields struct {
	id        string
	revision  Uint64String
	expiresAt string
}

func (f workSessionFields) parse() (WorkSession, error) {
	if err := ValidateWorkSessionID(f.id); err != nil {
		return WorkSession{}, err
	}
	// A session without an expiry carries none.
	var expiresAt time.Time
	if f.expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, f.expiresAt)
		if err != nil {
			return WorkSession{}, fmt.Errorf("invalid work session expiry: %w", err)
		}
		expiresAt = parsed
	}
	return WorkSession{ID: f.id, Revision: uint64(f.revision), ExpiresAt: expiresAt}, nil
}

// ValidateWorkSessionID accepts only a canonical UUID string, so the ID is
// safe to place in a URL path.
func ValidateWorkSessionID(id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id {
		return errors.New("work session ID is not a canonical UUID")
	}
	return nil
}
