package transporter

import (
	"fmt"
	"net/http"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

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
		// again would be rejected the same way. No error is returned, which
		// is what keeps the metric out of the retry queue, but the send did
		// not succeed either and saying nothing made it look like it had.
		//
		// Only the path and the status are logged. The response body can
		// quote the payload back, and the request carries the agent's
		// credentials, so neither belongs in a log line.
		log.Warn().Msgf("%s %s was rejected with %d; the metric is dropped.", http.MethodPost, url, statusCode)
		return nil
	}
	return fmt.Errorf("%s %s Error: %d %s", http.MethodPost, url, statusCode, resp)
}
