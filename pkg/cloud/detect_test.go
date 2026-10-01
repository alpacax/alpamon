package cloud

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider is a configurable in-memory Provider for testing Detect.
type fakeProvider struct {
	name       string
	probeOK    bool
	probeDelay time.Duration // sleep inside Probe to exercise ctx cancellation paths
	fetchMeta  *Metadata
	fetchErr   error
	probeCalls int
	fetchCalls int
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Probe(ctx context.Context) bool {
	f.probeCalls++
	if f.probeDelay > 0 {
		select {
		case <-time.After(f.probeDelay):
		case <-ctx.Done():
			return false
		}
	}
	return f.probeOK
}
func (f *fakeProvider) Fetch(_ context.Context) (*Metadata, error) {
	f.fetchCalls++
	return f.fetchMeta, f.fetchErr
}

func TestDetect_FirstProbeWinsAndReturnsMetadata(t *testing.T) {
	expected := &Metadata{Provider: ProviderAWS, InstanceID: "i-x"}
	aws := &fakeProvider{name: ProviderAWS, probeOK: true, fetchMeta: expected}
	gcp := &fakeProvider{name: ProviderGCP, probeOK: false}

	p, meta, err := Detect(context.Background(), []Provider{aws, gcp})
	require.NoError(t, err)
	assert.Equal(t, ProviderAWS, p.Name())
	assert.Same(t, expected, meta)
	assert.Equal(t, 0, gcp.probeCalls, "GCP should not be probed after AWS succeeds")
}

func TestDetect_AllProbesFail_ReturnsErr(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}
	azure := &fakeProvider{name: ProviderAzure}

	_, _, err := Detect(context.Background(), []Provider{aws, gcp, azure})
	assert.ErrorIs(t, err, ErrNoCloudProvider)
}

func TestDetect_FetchError_StillReturnsProvider(t *testing.T) {
	// Probe succeeds, Fetch returns partial Metadata + error. Detect surfaces
	// the error to the caller alongside the partial Metadata, and must NOT
	// fall through to another provider — host IS on AWS.
	partial := &Metadata{Provider: ProviderAWS}
	fetchErr := errors.New("partial fetch")
	aws := &fakeProvider{name: ProviderAWS, probeOK: true, fetchMeta: partial, fetchErr: fetchErr}
	gcp := &fakeProvider{name: ProviderGCP, probeOK: true, fetchMeta: &Metadata{Provider: ProviderGCP}}

	p, meta, err := Detect(context.Background(), []Provider{aws, gcp})
	assert.ErrorIs(t, err, fetchErr, "expected Detect to surface fetch error")
	assert.Equal(t, ProviderAWS, p.Name(), "Detect should stick with AWS")
	assert.Equal(t, ProviderAWS, meta.Provider)
	assert.Equal(t, 0, gcp.fetchCalls, "GCP must not be fetched after AWS probe succeeded")
}

func TestDetect_NilMetaFromFetch_ReturnsProviderOnlyMeta(t *testing.T) {
	// If a provider returns nil metadata + error, Detect must still surface
	// a non-nil Metadata so callers can call .ToTags() safely, and surface
	// the error so callers know detection was partial.
	fetchErr := errors.New("nil")
	aws := &fakeProvider{name: ProviderAWS, probeOK: true, fetchMeta: nil, fetchErr: fetchErr}

	_, meta, err := Detect(context.Background(), []Provider{aws})
	assert.ErrorIs(t, err, fetchErr, "expected Detect to surface fetch error")
	if assert.NotNil(t, meta, "expected non-nil meta with Provider=aws") {
		assert.Equal(t, ProviderAWS, meta.Provider, "expected non-nil meta with Provider=aws")
	}
}

func TestDetect_EmptyProviders(t *testing.T) {
	_, _, err := Detect(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNoCloudProvider)
}

func TestDetect_ContextCancelled(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := Detect(ctx, []Provider{aws})
	assert.Error(t, err, "expected ctx err when context cancelled before probe")
}

func TestDetect_ContextDeadlineRespectedBetweenProbes(t *testing.T) {
	// Two 30ms probes against a 50ms deadline. The returned error proves nothing here:
	// Detect's post-loop ctx.Err check reports DeadlineExceeded either way. The third
	// provider going unprobed is what shows the in-loop check survived.
	synctest.Test(t, func(t *testing.T) {
		newSlow := func() *fakeProvider {
			return &fakeProvider{name: ProviderAWS, probeOK: false, probeDelay: 30 * time.Millisecond}
		}
		first, second, third := newSlow(), newSlow(), newSlow()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, _, err := Detect(ctx, []Provider{first, second, third})
		elapsed := time.Since(start)

		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, 50*time.Millisecond, elapsed, "Detect ran past its deadline")
		assert.Zero(t, third.probeCalls, "the walk must stop at the deadline instead of draining every provider")
	})
}

func TestDetect_ContextExpiresDuringLastProbe_ReturnsCtxErr(t *testing.T) {
	// Regression: if ctx expires DURING the final provider's Probe (not before
	// the next iteration's top-of-loop check), Detect previously fell out and
	// returned ErrNoCloudProvider — losing the real ctx error. The fix is a
	// final ctx.Err() check before returning ErrNoCloudProvider.
	//
	// Setup: ctx deadline 30ms; single slow probe that sleeps 60ms. The probe
	// returns false (via its own ctx.Done case) AFTER ctx expires. Without the
	// post-loop ctx.Err() check, Detect would return ErrNoCloudProvider; with
	// the check it returns context.DeadlineExceeded.
	synctest.Test(t, func(t *testing.T) {
		slow := &fakeProvider{name: ProviderAWS, probeOK: false, probeDelay: 60 * time.Millisecond}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()

		_, _, err := Detect(ctx, []Provider{slow})
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.NotErrorIs(t, err, ErrNoCloudProvider, "must not collapse ctx deadline into ErrNoCloudProvider")
	})
}

func TestReorderByDMI_NoHint(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}
	azure := &fakeProvider{name: ProviderAzure}

	out := reorderByDMI([]Provider{aws, gcp, azure}, "")
	if assert.Len(t, out, 3, "reorder with empty hint should preserve order") {
		assert.Same(t, aws, out[0])
		assert.Same(t, gcp, out[1])
		assert.Same(t, azure, out[2])
	}
}

func TestReorderByDMI_HintMovesProviderToFront(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}
	azure := &fakeProvider{name: ProviderAzure}

	out := reorderByDMI([]Provider{aws, gcp, azure}, ProviderAzure)
	assert.Equal(t, ProviderAzure, out[0].Name(), "hint=azure should put azure first")
	// Other providers stay in relative order
	assert.Equal(t, ProviderAWS, out[1].Name(), "remaining order wrong")
	assert.Equal(t, ProviderGCP, out[2].Name(), "remaining order wrong")
}

func TestReorderByDMI_HintAlreadyFirst(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}

	out := reorderByDMI([]Provider{aws, gcp}, ProviderAWS)
	require.Len(t, out, 2)
	assert.Same(t, aws, out[0], "hint already first should preserve order")
	assert.Same(t, gcp, out[1], "hint already first should preserve order")
}

func TestReorderByDMI_HintNotMatched(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}

	out := reorderByDMI([]Provider{aws, gcp}, "unknown-provider")
	require.Len(t, out, 2)
	assert.Same(t, aws, out[0], "unmatched hint should preserve order")
	assert.Same(t, gcp, out[1], "unmatched hint should preserve order")
}

func TestClassifyDMI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Amazon EC2", ProviderAWS},
		{"amazon", ProviderAWS},
		{"AWS Nitro", ProviderAWS},
		{"Google", ProviderGCP},
		{"Google Compute Engine", ProviderGCP},
		{"Microsoft Corporation", ProviderAzure},
		{"  microsoft corporation\n", ProviderAzure},
		{"VMware, Inc.", ""},
		{"QEMU", ""},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, classifyDMI(c.in), "classifyDMI(%q)", c.in)
	}
}

func TestReadDMIHint_NonLinuxReturnsEmpty(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("skipping non-Linux path on Linux")
	}
	assert.Equal(t, "", readDMIHint(), "non-Linux readDMIHint should return empty")
}
