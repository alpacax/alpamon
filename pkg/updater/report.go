package updater

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// ReportURL receives the outcome of a pinned upgrade attempt. A server that
// predates it answers 404, which is logged and otherwise ignored.
const ReportURL = "/api/servers/agent-upgrades/report/"

// reportTimeoutSeconds is in seconds because the session multiplies it by
// time.Second itself.
const reportTimeoutSeconds = 10

// Outcome is the final state of an upgrade attempt.
type Outcome string

const (
	OutcomeSucceeded  Outcome = "succeeded"
	OutcomeFailed     Outcome = "failed"
	OutcomeRolledBack Outcome = "rolled_back"
)

// Report is the body posted to ReportURL.
type Report struct {
	AttemptID   string     `json:"attempt_id"`
	FromVersion string     `json:"from_version"`
	ToVersion   string     `json:"to_version"`
	Outcome     Outcome    `json:"outcome"`
	ErrorClass  ErrorClass `json:"error_class,omitempty"`
	Detail      string     `json:"detail,omitempty"`
}

// Poster is the subset of the API session a report needs.
type Poster interface {
	Post(url string, rawBody any, timeout time.Duration) ([]byte, int, error)
}

// SendReport posts r and reports whether it is settled. A report without an
// attempt ID has nothing to attach to and is not sent. A 404 or 410 means the
// server does not have the endpoint and counts as settled, so the caller does
// not retry against a server that will never accept it. Any other non-2xx
// answer is a failure the caller may retry.
func SendReport(p Poster, r Report) bool {
	if p == nil || r.AttemptID == "" {
		return true
	}
	_, status, err := p.Post(ReportURL, r, reportTimeoutSeconds)
	switch {
	case err != nil:
		log.Warn().Err(err).Str("attempt_id", r.AttemptID).Msg("Failed to send upgrade report.")
		return false
	case status == http.StatusNotFound || status == http.StatusGone:
		log.Info().Str("attempt_id", r.AttemptID).Msg("Server does not accept upgrade reports yet; skipping.")
		return true
	case status < 200 || status >= 300:
		log.Warn().Int("status_code", status).Str("attempt_id", r.AttemptID).Msg("Upgrade report was rejected.")
		return false
	}
	log.Info().Str("attempt_id", r.AttemptID).Str("outcome", string(r.Outcome)).Msg("Upgrade report sent.")
	return true
}
