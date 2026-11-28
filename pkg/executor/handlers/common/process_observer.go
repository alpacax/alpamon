package common

import "context"

type processObserverKey struct{}

// WithProcessObserver binds process ownership tracking to every executor call
// using ctx. The observer runs after Start; on Unix, the child leads a new session.
func WithProcessObserver(ctx context.Context, observer func(commandID string, pid int)) context.Context {
	return context.WithValue(ctx, processObserverKey{}, observer)
}

// ProcessObserverFromContext returns the process observer bound to ctx, or nil
// when the execution has no process owner.
func ProcessObserverFromContext(ctx context.Context) func(commandID string, pid int) {
	observer, _ := ctx.Value(processObserverKey{}).(func(string, int))
	return observer
}
