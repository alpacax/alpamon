package transporter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogs redirects the global logger into a buffer for the duration of
// the test, so a test can assert on what was logged and how often.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = previousLogger
		zerolog.SetGlobalLevel(previousLevel)
	})

	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	return &buf
}

// newTestTransporter returns a Transporter pointed at a server that answers
// every request with status and body, and a counter of the requests it saw.
func newTestTransporter(t *testing.T, status int, body string) (*Transporter, *atomic.Int64) {
	t.Helper()

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	session := &scheduler.Session{BaseURL: server.URL, Client: server.Client(), Authorization: `id="agent-id", key="agent-key"`}

	return NewTransporter(session, NewURLResolver()), &requests
}

func testMetric() base.MetricData {
	return base.MetricData{
		Type: base.CPU,
		Data: []base.CheckResult{{Timestamp: time.Now(), Usage: 1}},
	}
}

// A 400 means the server refused the payload, so the metric is not retried.
// It is still a send that did not happen, and it used to leave no trace at
// all.
func TestSend_LogsARejectedPayloadAndDoesNotRetryIt(t *testing.T) {
	logs := captureLogs(t)
	transporter, requests := newTestTransporter(t, http.StatusBadRequest, `{"usage":["a value is required"]}`)

	err := transporter.Send(testMetric())

	require.NoError(t, err, "a 400 is not an error the caller should retry")
	assert.Equal(t, int64(1), requests.Load(), "the metric is sent once and not again")

	logged := logs.String()
	assert.Equal(t, 1, strings.Count(logged, `"level":"warn"`), "one line per rejected response")
	assert.Contains(t, logged, cpuURL, "the line names the endpoint that refused the metric")
	assert.Contains(t, logged, "400", "the line names the status")
}

// The response body can quote the payload back, and the request carries the
// agent's credentials. Neither belongs in a log line.
func TestSend_KeepsTheRejectionBodyAndCredentialsOutOfTheLog(t *testing.T) {
	logs := captureLogs(t)
	transporter, _ := newTestTransporter(t, http.StatusBadRequest, "payload-echoed-back")

	require.NoError(t, transporter.Send(testMetric()))

	logged := logs.String()
	assert.NotContains(t, logged, "payload-echoed-back")
	assert.NotContains(t, logged, "agent-key")
}

// Every other rejection still comes back as an error, which is what puts the
// metric on the retry queue.
func TestSend_ServerErrorIsStillAnError(t *testing.T) {
	logs := captureLogs(t)
	transporter, requests := newTestTransporter(t, http.StatusInternalServerError, "boom")

	err := transporter.Send(testMetric())

	require.Error(t, err)
	assert.ErrorContains(t, err, "500")
	assert.Equal(t, int64(1), requests.Load())
	assert.NotContains(t, logs.String(), `"level":"warn"`, "a 5xx is reported to the caller, not logged here")
}

// A transport that never answered is an error too, and a different one from
// a refused payload.
func TestSend_TransportFailureIsStillAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	session := &scheduler.Session{BaseURL: server.URL, Client: server.Client()}
	transporter := NewTransporter(session, NewURLResolver())
	server.Close()

	assert.Error(t, transporter.Send(testMetric()))
}

func TestSend_SuccessIsSilent(t *testing.T) {
	logs := captureLogs(t)
	transporter, requests := newTestTransporter(t, http.StatusCreated, "")

	require.NoError(t, transporter.Send(testMetric()))
	assert.Equal(t, int64(1), requests.Load())
	assert.Empty(t, logs.String())
}
