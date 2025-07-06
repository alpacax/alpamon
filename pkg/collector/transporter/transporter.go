package transporter

import (
	"fmt"
	"net/http"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
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
	url, err := t.resolver.ResolveURL(data.Type)
	if err != nil {
		return err
	}

	resp, statusCode, err := t.session.Post(url, data.Data, 10)
	if err != nil {
		return err
	} else if utils.IsSuccessStatusCode(statusCode) {
		return nil
	} else {
		if statusCode == http.StatusBadRequest {
			return nil
		} else {
			return fmt.Errorf("%s %s Error: %d %s", http.MethodPost, url, statusCode, resp)
		}
	}
}
