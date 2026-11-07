//go:build linux

package exposure

import "context"

// Supported reports whether this build collects and sends the exposure
// report.
const Supported = true

// Start runs the exposure reads until ctx ends: one every hour with up to
// five minutes of jitter, plus one per Trigger. It does not depend on
// alpamon-pam or on any policy setting.
func Start(ctx context.Context, p Poster) {
	opts := defaultOptions()
	if testHookStartOptions != nil {
		opts = *testHookStartOptions
	}
	c := newCollector(opts)
	s := newService(p, c.collect, triggers)
	go s.run(ctx)
}

// Trigger asks for one exposure read: after the commissioning sync, and for
// a sync command whose keys name "exposure". A trigger during a read causes
// exactly one more read after it.
func Trigger() {
	select {
	case triggers <- struct{}{}:
	default:
	}
}

// triggers holds at most one pending read request: a request that arrives
// while one is already pending is the same request.
var triggers = make(chan struct{}, 1)

// testHookStartOptions lets the process test use a fixture host with the
// real Start lifecycle, regardless of the test process's privileges.
var testHookStartOptions *collectorOptions
