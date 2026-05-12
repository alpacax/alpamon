package cloud

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
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
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if p.Name() != ProviderAWS {
		t.Errorf("provider = %q, want aws", p.Name())
	}
	if meta != expected {
		t.Errorf("meta = %+v, want %+v", meta, expected)
	}
	if gcp.probeCalls != 0 {
		t.Errorf("GCP should not be probed after AWS succeeds, got %d", gcp.probeCalls)
	}
}

func TestDetect_AllProbesFail_ReturnsErr(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}
	azure := &fakeProvider{name: ProviderAzure}

	_, _, err := Detect(context.Background(), []Provider{aws, gcp, azure})
	if !errors.Is(err, ErrNoCloudProvider) {
		t.Errorf("err = %v, want ErrNoCloudProvider", err)
	}
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
	if !errors.Is(err, fetchErr) {
		t.Errorf("expected Detect to surface fetch error, got %v", err)
	}
	if p.Name() != ProviderAWS {
		t.Errorf("Detect fell through to %q; should stick with AWS", p.Name())
	}
	if meta.Provider != ProviderAWS {
		t.Errorf("meta.Provider = %q, want aws", meta.Provider)
	}
	if gcp.fetchCalls != 0 {
		t.Error("GCP must not be fetched after AWS probe succeeded")
	}
}

func TestDetect_NilMetaFromFetch_ReturnsProviderOnlyMeta(t *testing.T) {
	// If a provider returns nil metadata + error, Detect must still surface
	// a non-nil Metadata so callers can call .ToTags() safely, and surface
	// the error so callers know detection was partial.
	fetchErr := errors.New("nil")
	aws := &fakeProvider{name: ProviderAWS, probeOK: true, fetchMeta: nil, fetchErr: fetchErr}

	_, meta, err := Detect(context.Background(), []Provider{aws})
	if !errors.Is(err, fetchErr) {
		t.Errorf("expected Detect to surface fetch error, got %v", err)
	}
	if meta == nil || meta.Provider != ProviderAWS {
		t.Errorf("expected non-nil meta with Provider=aws, got %+v", meta)
	}
}

func TestDetect_EmptyProviders(t *testing.T) {
	_, _, err := Detect(context.Background(), nil)
	if !errors.Is(err, ErrNoCloudProvider) {
		t.Errorf("err = %v, want ErrNoCloudProvider", err)
	}
}

func TestDetect_ContextCancelled(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := Detect(ctx, []Provider{aws})
	if err == nil {
		t.Error("expected ctx err when context cancelled before probe")
	}
}

func TestDetect_ContextDeadlineRespectedBetweenProbes(t *testing.T) {
	// Each fake probe sleeps 30ms; ctx deadline is 50ms. With the in-loop
	// ctx.Err short-circuit working correctly, Detect returns
	// context.DeadlineExceeded after 1-2 probes — not ErrNoCloudProvider.
	//
	// If the short-circuit regresses (e.g. the ctx.Err check is removed),
	// each probe still returns quickly via its own ctx.Done case, the loop
	// drains all providers, and Detect falls out with ErrNoCloudProvider.
	// Tolerating ErrNoCloudProvider here would silently accept that
	// regression, so the assertion requires DeadlineExceeded strictly.
	slow := func() *fakeProvider {
		return &fakeProvider{name: ProviderAWS, probeOK: false, probeDelay: 30 * time.Millisecond}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := Detect(ctx, []Provider{slow(), slow(), slow()})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
	// Upper bound guards against the regression where Detect ignores the
	// deadline and serializes all probes (3 * 30ms = 90ms). Generous slack
	// for CI scheduling jitter.
	if elapsed > 200*time.Millisecond {
		t.Errorf("Detect ran for %v; ctx short-circuit appears broken", elapsed)
	}
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
	slow := &fakeProvider{name: ProviderAWS, probeOK: false, probeDelay: 60 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, _, err := Detect(ctx, []Provider{slow})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
	if errors.Is(err, ErrNoCloudProvider) {
		t.Error("must not collapse ctx deadline into ErrNoCloudProvider")
	}
}

func TestReorderByDMI_NoHint(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}
	azure := &fakeProvider{name: ProviderAzure}

	out := reorderByDMI([]Provider{aws, gcp, azure}, "")
	if len(out) != 3 || out[0] != aws || out[1] != gcp || out[2] != azure {
		t.Errorf("reorder with empty hint should preserve order, got %v", out)
	}
}

func TestReorderByDMI_HintMovesProviderToFront(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}
	azure := &fakeProvider{name: ProviderAzure}

	out := reorderByDMI([]Provider{aws, gcp, azure}, ProviderAzure)
	if out[0].Name() != ProviderAzure {
		t.Errorf("hint=azure should put azure first; got %q", out[0].Name())
	}
	// Other providers stay in relative order
	if out[1].Name() != ProviderAWS || out[2].Name() != ProviderGCP {
		t.Errorf("remaining order wrong: got %q, %q", out[1].Name(), out[2].Name())
	}
}

func TestReorderByDMI_HintAlreadyFirst(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}

	out := reorderByDMI([]Provider{aws, gcp}, ProviderAWS)
	if out[0] != aws || out[1] != gcp {
		t.Errorf("hint already first should preserve order")
	}
}

func TestReorderByDMI_HintNotMatched(t *testing.T) {
	aws := &fakeProvider{name: ProviderAWS}
	gcp := &fakeProvider{name: ProviderGCP}

	out := reorderByDMI([]Provider{aws, gcp}, "unknown-provider")
	if out[0] != aws || out[1] != gcp {
		t.Errorf("unmatched hint should preserve order")
	}
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
		if got := classifyDMI(c.in); got != c.want {
			t.Errorf("classifyDMI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadDMIHint_NonLinuxReturnsEmpty(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("skipping non-Linux path on Linux")
	}
	if got := readDMIHint(); got != "" {
		t.Errorf("non-Linux readDMIHint should return \"\", got %q", got)
	}
}
