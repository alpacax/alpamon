// Package safego keeps a panic in one goroutine from ending the whole agent.
package safego

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// Go runs fn on a new goroutine. A panic in fn is logged under name, then
// onPanic, when not nil, runs to leave fn's work closed instead of hung.
func Go(name string, fn func(), onPanic func()) {
	go func() {
		defer Recover(name, onPanic)
		fn()
	}()
}

// Recover does what Go does for the function it guards. Defer it directly,
// as that function's first defer, so it runs after the others.
func Recover(name string, onPanic func()) {
	r := recover()
	if r == nil {
		return
	}
	desc := Describe(r)
	// The message repeats the name and panic: the server's copy of the record keeps only the message.
	log.Error().Str("goroutine", name).Str("panic", desc).Str("stack", string(debug.Stack())).
		Msgf("Recovered a panic in %s: %s", name, desc)
	if onPanic != nil {
		defer recoverCleanup(name)
		onPanic()
	}
}

// recoverCleanup logs a panic in onPanic, which would otherwise end the agent.
func recoverCleanup(name string) {
	if r := recover(); r != nil {
		desc := Describe(r)
		log.Error().Str("goroutine", name).Str("panic", desc).Str("stack", string(debug.Stack())).
			Msgf("Recovered a panic in the panic cleanup of %s: %s", name, desc)
	}
}

// Describe names a panic value for a log: its type, plus the message of a
// runtime error. Any other value may carry session data, so it is not printed.
func Describe(r any) (desc string) {
	desc = fmt.Sprintf("%T", r)
	if err, ok := r.(runtime.Error); ok {
		defer func() { _ = recover() }() // an Error method that panics leaves the type alone
		desc += ": " + err.Error()
	}
	return desc
}
