package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type azureMockOpts struct {
	requireHeader  bool
	requireVersion bool
	instanceStatus int
	instanceBody   string
	zone           string
	subscription   string
	vmID           string
	vmSize         string
	location       string
}

func newAzureMockServer(t *testing.T, opts azureMockOpts) *httptest.Server {
	t.Helper()

	if opts.instanceStatus == 0 {
		opts.instanceStatus = http.StatusOK
	}
	if opts.vmID == "" {
		opts.vmID = "11111111-2222-3333-4444-555555555555"
	}
	if opts.location == "" {
		opts.location = "eastus"
	}
	if opts.vmSize == "" {
		opts.vmSize = "Standard_D2s_v3"
	}
	if opts.subscription == "" {
		opts.subscription = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	}

	if opts.instanceBody == "" {
		body := azureInstanceResponse{}
		body.Compute.VMID = opts.vmID
		body.Compute.Location = opts.location
		body.Compute.Zone = opts.zone
		body.Compute.VMSize = opts.vmSize
		body.Compute.SubscriptionID = opts.subscription
		buf, _ := json.Marshal(body)
		opts.instanceBody = string(buf)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(azureInstancePath, func(w http.ResponseWriter, r *http.Request) {
		if opts.requireHeader && r.Header.Get(azureHdrMetadata) != azureHdrValue {
			http.Error(w, "missing Metadata header", http.StatusBadRequest)
			return
		}
		if opts.requireVersion && r.URL.Query().Get("api-version") == "" {
			http.Error(w, "missing api-version", http.StatusBadRequest)
			return
		}
		w.WriteHeader(opts.instanceStatus)
		_, _ = w.Write([]byte(opts.instanceBody))
	})

	return httptest.NewServer(mux)
}

func TestAzure_Fetch_HappyPath(t *testing.T) {
	server := newAzureMockServer(t, azureMockOpts{
		requireHeader:  true,
		requireVersion: true,
		zone:           "2",
	})
	defer server.Close()

	p := NewAzureWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	checks := map[string]string{
		"Provider":         ProviderAzure,
		"InstanceID":       "11111111-2222-3333-4444-555555555555",
		"Region":           "eastus",
		"AvailabilityZone": "2",
		"InstanceType":     "Standard_D2s_v3",
		"AccountID":        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
	got := map[string]string{
		"Provider":         meta.Provider,
		"InstanceID":       meta.InstanceID,
		"Region":           meta.Region,
		"AvailabilityZone": meta.AvailabilityZone,
		"InstanceType":     meta.InstanceType,
		"AccountID":        meta.AccountID,
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	if meta.NetworkID != "" {
		t.Errorf("NetworkID expected empty for Azure V1, got %q", meta.NetworkID)
	}
}

func TestAzure_Fetch_ZoneEmpty(t *testing.T) {
	server := newAzureMockServer(t, azureMockOpts{zone: ""})
	defer server.Close()

	meta, err := NewAzureWithBase(server.URL).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta.AvailabilityZone != "" {
		t.Errorf("AZ should be empty for zone-less VM, got %q", meta.AvailabilityZone)
	}
}

func TestAzure_Probe_RejectsWithoutHeader(t *testing.T) {
	server := newAzureMockServer(t, azureMockOpts{requireHeader: true})
	defer server.Close()

	p := NewAzureWithBase(server.URL)
	if !p.Probe(context.Background()) {
		t.Error("Probe should succeed when client sends Metadata: true")
	}
}

func TestAzure_HeaderEnforcedByServer(t *testing.T) {
	// If our client failed to send Metadata: true, this server would 400.
	// We sanity-check that Probe still works.
	server := newAzureMockServer(t, azureMockOpts{requireHeader: true})
	defer server.Close()

	if !NewAzureWithBase(server.URL).Probe(context.Background()) {
		t.Error("Probe failed: header not being sent?")
	}
}

func TestAzure_Fetch_ServerErrorReturnsPartial(t *testing.T) {
	server := newAzureMockServer(t, azureMockOpts{instanceStatus: http.StatusServiceUnavailable})
	defer server.Close()

	p := NewAzureWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on 503")
	}
	if meta == nil || meta.Provider != ProviderAzure {
		t.Errorf("expected partial Metadata with Provider=azure, got %+v", meta)
	}
}

func TestAzure_Fetch_BadJSON(t *testing.T) {
	server := newAzureMockServer(t, azureMockOpts{instanceBody: "{not valid"})
	defer server.Close()

	_, err := NewAzureWithBase(server.URL).Fetch(context.Background())
	if err == nil {
		t.Error("expected parse error")
	}
}
