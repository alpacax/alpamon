package common

import (
	"context"
	"fmt"
	"time"
)

// Default timeouts for each handler domain.
// Each handler applies its own timeout via context.WithTimeout,
// rather than relying on a global pool timeout.
const (
	ShellTimeout      = 30 * time.Minute
	UpgradeTimeout    = 30 * time.Minute
	SystemCmdTimeout  = 60 * time.Second
	FileTimeout       = 10 * time.Minute
	FirewallTimeout   = 2 * time.Minute
	UserTimeout       = 2 * time.Minute
	UserDeleteTimeout = 5 * time.Minute
	GroupTimeout      = 30 * time.Second
	InfoTimeout       = 30 * time.Second
)

// TimeoutResult is returned when a handler-level timeout is exceeded.
const TimeoutExitCode = 124

// WithHandlerTimeout wraps ctx with the given timeout and returns a
// context and cancel func. Use IsTimeout to check if the context
// deadline was exceeded, and TimeoutError to produce a standard
// timeout response (exit 124).
func WithHandlerTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// IsTimeout returns true if the context error indicates a deadline exceeded.
func IsTimeout(ctx context.Context) bool {
	return ctx.Err() == context.DeadlineExceeded
}

// TimeoutError returns a standard timeout response (exit 124 + message).
func TimeoutError(timeout time.Duration) (int, string, error) {
	return TimeoutExitCode, fmt.Sprintf("Command timed out after %s", timeout.Truncate(time.Second)), context.DeadlineExceeded
}
