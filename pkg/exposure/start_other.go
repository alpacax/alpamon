//go:build !linux

package exposure

import (
	"context"
)

// Supported reports whether this build collects and sends the exposure
// report. Only Linux does in this version.
const Supported = false

// Start does nothing on this platform: neither endpoint is ever called.
func Start(context.Context, Poster) {}

// Trigger does nothing on this platform.
func Trigger() {}
