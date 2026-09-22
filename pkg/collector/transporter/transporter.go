package transporter

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// ErrRejected is Send's error for an HTTP 400: the server rejected the
// payload itself, so the same bytes would be rejected again and a caller
// must not retry it. It is still not a delivery, so a caller that counts
// what reached the server rather than what merely stopped retrying—like
// Collector.flushPending—must not count it as sent. errors.Is matches it
// through any wrapping.
var ErrRejected = errors.New("metric payload rejected")

type TransportStrategy interface {
	Send(data base.MetricData) error
}

type TransporterFactory interface {
	CreateTransporter(session *scheduler.Session) (TransportStrategy, error)
}

type DefaultTransporterFactory struct {
	resolver *URLResolver
}

func NewDefaultTransporterFactory(resolver *URLResolver) *DefaultTransporterFactory {
	return &DefaultTransporterFactory{resolver: resolver}
}

// TODO: Support for various transporters will be required in the future
func (f *DefaultTransporterFactory) CreateTransporter(session *scheduler.Session) (TransportStrategy, error) {
	return NewTransporter(session, f.resolver), nil
}

type Transporter struct {
	session  *scheduler.Session
	resolver *URLResolver
}

func NewTransporter(session *scheduler.Session, resolver *URLResolver) *Transporter {
	return &Transporter{
		session:  session,
		resolver: resolver,
	}
}

func (t *Transporter) Send(data base.MetricData) error {
	if len(data.Data) == 0 {
		return nil
	}

	url, err := t.resolver.ResolveURL(data.Type)
	if err != nil {
		return err
	}

	resp, statusCode, err := t.session.Post(url, data.Data, 10)
	if err != nil {
		return err
	}
	if utils.IsSuccessStatusCode(statusCode) {
		return nil
	}
	if statusCode == http.StatusBadRequest {
		// The server rejected the payload itself, so sending the same bytes
		// again would be rejected the same way. ErrRejected is what keeps
		// the metric out of the retry queue—callers that retry on error
		// must treat it like a nil error—but the send did not succeed
		// either, and returning plain nil made it look like it had.
		//
		// Only the path and the status are logged. The response body can
		// quote the payload back, and the request carries the agent's
		// credentials, so neither belongs in a log line.
		log.Warn().Msgf("%s %s was rejected with %d; the metric is dropped.", http.MethodPost, url, statusCode)
		return ErrRejected
	}
	return fmt.Errorf("%s %s Error: %d %s", http.MethodPost, url, statusCode, resp)
}
