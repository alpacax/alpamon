package common

import (
	"context"
	"fmt"
	"strings"
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

// TimeoutExitCode is returned when a handler-level timeout is exceeded.
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
	return TimeoutExitCode, FormatTimeoutBanner(timeout), context.DeadlineExceeded
}

// timeoutBannerPrefix is the fixed portion of FormatTimeoutBanner's output,
// used by StripTimeoutBanner to recognize and remove one.
const timeoutBannerPrefix = "Command timed out after "

// FormatTimeoutBanner is the single source of truth for the timeout banner text.
func FormatTimeoutBanner(elapsed time.Duration) string {
	return fmt.Sprintf("%s%s", timeoutBannerPrefix, elapsed.Truncate(time.Second))
}

// StripTimeoutBanner removes a trailing banner appended by FormatTimeoutBanner
// (and its "\n\n" separator, when present), so a caller can replace it with its own.
func StripTimeoutBanner(out string) string {
	if idx := strings.LastIndex(out, "\n\n"+timeoutBannerPrefix); idx >= 0 {
		return out[:idx]
	}
	if strings.HasPrefix(out, timeoutBannerPrefix) {
		return ""
	}
	return out
}
