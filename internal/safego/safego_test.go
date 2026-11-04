package safego

import (
	"bytes"
	"fmt"
	"testing"
	"testing/synctest"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { log.Logger = prev; zerolog.SetGlobalLevel(prevLevel) })
	return &buf
}

func TestGoLogsAPanicAndRunsOnPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logged := captureLog(t)
		cleaned := make(chan struct{})

		Go("test worker", func() { panic("boom") }, func() { close(cleaned) })

		<-cleaned
		assert.Contains(t, logged.String(), `"goroutine":"test worker"`)
		assert.Contains(t, logged.String(), `"panic":"string"`)
		assert.Contains(t, logged.String(), `"stack":`)
		assert.Contains(t, logged.String(), `"message":"Recovered a panic in test worker: string"`, "the server keeps only the message")
	})
}

func TestGoSkipsOnPanicWhenFnReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logged := captureLog(t)
		cleaned := false

		Go("test worker", func() {}, func() { cleaned = true })

		synctest.Wait()
		assert.False(t, cleaned)
		assert.Empty(t, logged.String())
	})
}

func TestGoSurvivesAPanicWithoutOnPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logged := captureLog(t)

		Go("test worker", func() { panic("boom") }, nil)

		synctest.Wait() // an unrecovered panic would have ended the test binary here
		assert.Contains(t, logged.String(), `"goroutine":"test worker"`)
	})
}

func TestGoSurvivesAPanicInOnPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logged := captureLog(t)

		Go("test worker", func() { panic("boom") }, func() { panic("cleanup boom") })

		synctest.Wait() // an unrecovered panic would have ended the test binary here
		assert.Contains(t, logged.String(), "Recovered a panic in the panic cleanup of test worker: string")
	})
}

func TestDescribeKeepsARuntimeErrorsMessage(t *testing.T) {
	var r any
	func() {
		defer func() { r = recover() }()
		var s []int
		_ = s[len(s)]
	}()

	assert.Contains(t, Describe(r), "index out of range [0] with length 0")
}

func TestDescribeHidesWhatACustomValueCarries(t *testing.T) {
	got := Describe(fmt.Errorf("open %s: denied", "/home/alice/secret"))

	assert.Contains(t, got, "error")
	assert.NotContains(t, got, "denied")
	assert.NotContains(t, got, "alice")
}

type panickingRuntimeError struct{}

func (panickingRuntimeError) RuntimeError() {}
func (panickingRuntimeError) Error() string { panic("Error panicked") }

func TestDescribeSurvivesARuntimeErrorWhoseErrorPanics(t *testing.T) {
	var got string

	assert.NotPanics(t, func() { got = Describe(panickingRuntimeError{}) })
	assert.Equal(t, "safego.panickingRuntimeError", got)
}

func TestDescribeSurvivesATypedNilRuntimeError(t *testing.T) {
	var nilErr *panickingRuntimeError
	var got string

	assert.NotPanics(t, func() { got = Describe(nilErr) })
	assert.Equal(t, "*safego.panickingRuntimeError", got)
}
