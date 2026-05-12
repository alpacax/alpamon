package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type gcpMockOpts struct {
	requireFlavor      bool // server enforces request Metadata-Flavor header
	omitFlavorResponse bool // server does NOT echo Metadata-Flavor in responses (simulates non-GCE 200)
	instanceIDStatus   int
	instanceIDBody     string
	zoneStatus         int
	zoneBody           string
	machineStatus      int
	machineBody        string
	networkStatus      int
	networkBody        string
	projectStatus      int
	projectBody        string
}

func newGCPMockServer(t *testing.T, opts gcpMockOpts) *httptest.Server {
	t.Helper()

	if opts.instanceIDStatus == 0 {
		opts.instanceIDStatus = http.StatusOK
	}
	if opts.instanceIDBody == "" {
		opts.instanceIDBody = "1234567890123456789"
	}
	if opts.zoneStatus == 0 {
		opts.zoneStatus = http.StatusOK
	}
	if opts.zoneBody == "" {
		opts.zoneBody = "projects/123/zones/us-central1-a"
	}
	if opts.machineStatus == 0 {
		opts.machineStatus = http.StatusOK
	}
	if opts.machineBody == "" {
		opts.machineBody = "projects/123/machineTypes/e2-medium"
	}
	if opts.networkStatus == 0 {
		opts.networkStatus = http.StatusOK
	}
	if opts.networkBody == "" {
		opts.networkBody = "projects/123/networks/default"
	}
	if opts.projectStatus == 0 {
		opts.projectStatus = http.StatusOK
	}
	if opts.projectBody == "" {
		opts.projectBody = "my-project"
	}

	mux := http.NewServeMux()
	guard := func(w http.ResponseWriter, r *http.Request) bool {
		if opts.requireFlavor && r.Header.Get(gcpFlavorHeader) != gcpFlavorValue {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return false
		}
		// Real GCE echoes Metadata-Flavor: Google in successful responses; mimic
		// unless the test explicitly opts out to verify client-side rejection.
		if !opts.omitFlavorResponse {
			w.Header().Set(gcpFlavorHeader, gcpFlavorValue)
		}
		return true
	}

	mux.HandleFunc(gcpInstanceIDPath, func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		w.WriteHeader(opts.instanceIDStatus)
		_, _ = w.Write([]byte(opts.instanceIDBody))
	})
	mux.HandleFunc(gcpZonePath, func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		w.WriteHeader(opts.zoneStatus)
		_, _ = w.Write([]byte(opts.zoneBody))
	})
	mux.HandleFunc(gcpMachineTypePath, func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		w.WriteHeader(opts.machineStatus)
		_, _ = w.Write([]byte(opts.machineBody))
	})
	mux.HandleFunc(gcpNetworkPath, func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		w.WriteHeader(opts.networkStatus)
		_, _ = w.Write([]byte(opts.networkBody))
	})
	mux.HandleFunc(gcpProjectIDPath, func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		w.WriteHeader(opts.projectStatus)
		_, _ = w.Write([]byte(opts.projectBody))
	})

	return httptest.NewServer(mux)
}

func TestGCP_Fetch_HappyPath(t *testing.T) {
	server := newGCPMockServer(t, gcpMockOpts{requireFlavor: true})
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	checks := map[string]string{
		"Provider":         ProviderGCP,
		"InstanceID":       "1234567890123456789",
		"Region":           "us-central1",
		"AvailabilityZone": "us-central1-a",
		"InstanceType":     "e2-medium",
		"NetworkID":        "default",
		"AccountID":        "my-project",
	}
	got := map[string]string{
		"Provider":         meta.Provider,
		"InstanceID":       meta.InstanceID,
		"Region":           meta.Region,
		"AvailabilityZone": meta.AvailabilityZone,
		"InstanceType":     meta.InstanceType,
		"NetworkID":        meta.NetworkID,
		"AccountID":        meta.AccountID,
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func TestGCP_Probe_SucceedsAgainstFlavorEnforcingServer(t *testing.T) {
	// Integration sanity: a server that requires Metadata-Flavor: Google
	// (mimicking real GCE) accepts our request, so Probe succeeds.
	server := newGCPMockServer(t, gcpMockOpts{requireFlavor: true})
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	if !p.Probe(context.Background()) {
		t.Error("Probe should pass against a flavor-enforcing server when our client sends the header")
	}
}

func TestGCP_Probe_FlavorEnforcementBreaksOnAWS(t *testing.T) {
	// Simulate hitting AWS IMDS by mistake: it returns 401 on this path.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	if p.Probe(context.Background()) {
		t.Error("Probe should fail when server doesn't recognize GCP paths")
	}
}

func TestZoneToRegion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// real GCE zones — strip trailing single-letter suffix
		{"us-central1-a", "us-central1"},
		{"asia-northeast1-b", "asia-northeast1"},
		{"us-east4-c", "us-east4"},
		// region-only inputs must NOT be stripped (the previous implementation
		// chopped "us-central1" to "us")
		{"us-central1", "us-central1"},
		{"asia-northeast1", "asia-northeast1"},
		// edge cases
		{"region", "region"}, // no dash
		{"", ""},             // empty
		// multi-character trailing segment is treated as not-a-zone
		{"us-central1-ab", "us-central1-ab"},
	}
	for _, c := range cases {
		if got := zoneToRegion(c.in); got != c.want {
			t.Errorf("zoneToRegion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGCP_Probe_RejectsResponseWithoutFlavorHeader(t *testing.T) {
	// A captive portal / spoofed listener can return 200 + body without the
	// Metadata-Flavor: Google response header. Probe must reject this so we
	// don't false-positive non-GCE hosts.
	server := newGCPMockServer(t, gcpMockOpts{omitFlavorResponse: true})
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	if p.Probe(context.Background()) {
		t.Error("Probe should fail when response is missing Metadata-Flavor: Google header")
	}
}

func TestGCP_Fetch_ProjectIDFailure_OtherFieldsStillReturned(t *testing.T) {
	server := newGCPMockServer(t, gcpMockOpts{projectStatus: http.StatusNotFound})
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta.InstanceID == "" {
		t.Error("InstanceID should be populated even when project-id 404s")
	}
	if meta.AccountID != "" {
		t.Errorf("AccountID should be empty on project-id 404, got %q", meta.AccountID)
	}
}

func TestGCP_Fetch_EmptyInstanceID_ReturnsError(t *testing.T) {
	// IMDS returns 200 with empty body for instance-id. Fetch must surface
	// that as an error since cloud:instance_id is the deterministic-match
	// key for reconcile.
	server := newGCPMockServer(t, gcpMockOpts{instanceIDBody: "   "})
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when instance_id is empty/whitespace")
	}
	if meta == nil || meta.Provider != ProviderGCP {
		t.Errorf("expected partial Metadata with Provider=gcp, got %+v", meta)
	}
}

func TestGCP_Fetch_InstanceIDFailureAbortsWithError(t *testing.T) {
	server := newGCPMockServer(t, gcpMockOpts{instanceIDStatus: http.StatusInternalServerError})
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when instance-id endpoint 500s")
	}
}

func TestGCP_Fetch_ZoneEdgeCases(t *testing.T) {
	cases := []struct {
		body       string
		wantRegion string
		wantZone   string
	}{
		{"projects/123/zones/us-central1-a", "us-central1", "us-central1-a"},
		{"projects/999/zones/asia-northeast1-b", "asia-northeast1", "asia-northeast1-b"},
		{"us-east4-c", "us-east4", "us-east4-c"}, // already a basename
	}

	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			server := newGCPMockServer(t, gcpMockOpts{zoneBody: tc.body})
			defer server.Close()

			meta, err := NewGCPWithBase(server.URL).Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if meta.AvailabilityZone != tc.wantZone {
				t.Errorf("zone = %q, want %q", meta.AvailabilityZone, tc.wantZone)
			}
			if meta.Region != tc.wantRegion {
				t.Errorf("region = %q, want %q", meta.Region, tc.wantRegion)
			}
		})
	}
}

func TestGCP_FlavorHeader_AlwaysSent(t *testing.T) {
	var seenHeader atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader.Store(r.Header.Get(gcpFlavorHeader))
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	p := NewGCPWithBase(server.URL)
	_ = p.Probe(context.Background())
	if got := seenHeader.Load(); got != gcpFlavorValue {
		t.Errorf("Metadata-Flavor header = %q, want %q", got, gcpFlavorValue)
	}
}
