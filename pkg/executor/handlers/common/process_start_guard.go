package common

import "context"

type processStartGuardKey struct{}

// WithProcessStartGuard binds a guard that rechecks whether a process may start.
// A successful guard holds its permission until the returned release is called
// after process ownership is registered, or when startup fails.
func WithProcessStartGuard(ctx context.Context, guard func() (release func(), err error)) context.Context {
	return context.WithValue(ctx, processStartGuardKey{}, guard)
}

// ProcessStartGuardFromContext returns the process start guard bound to ctx.
func ProcessStartGuardFromContext(ctx context.Context) func() (release func(), err error) {
	guard, _ := ctx.Value(processStartGuardKey{}).(func() (func(), error))
	return guard
}
