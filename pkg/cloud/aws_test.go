package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// awsTestMAC is the MAC the mock IMDS returns for the primary ENI.
const awsTestMAC = "06:00:00:00:00:01"

// newAWSMockServer returns an httptest server that mimics the IMDSv2 protocol.
// Handlers can override individual paths by setting fields on opts.
type awsMockOpts struct {
	tokenStatus    int
	tokenBody      string
	requireToken   bool
	documentStatus int
	documentBody   string
	macStatus      int
	macBody        string
	vpcStatus      int
	vpcBody        string
}

func newAWSMockServer(t *testing.T, opts awsMockOpts) *httptest.Server {
	t.Helper()

	if opts.tokenStatus == 0 {
		opts.tokenStatus = http.StatusOK
	}
	if opts.tokenBody == "" {
		opts.tokenBody = "TOKEN-xxx"
	}
	if opts.documentStatus == 0 {
		opts.documentStatus = http.StatusOK
	}
	if opts.documentBody == "" {
		doc := awsIdentityDocument{
			InstanceID:       "i-0123456789abcdef0",
			Region:           "us-east-1",
			AvailabilityZone: "us-east-1a",
			InstanceType:     "t3.micro",
			AccountID:        "123456789012",
		}
		buf, _ := json.Marshal(doc)
		opts.documentBody = string(buf)
	}
	if opts.macStatus == 0 {
		opts.macStatus = http.StatusOK
	}
	if opts.macBody == "" {
		opts.macBody = awsTestMAC
	}
	if opts.vpcStatus == 0 {
		opts.vpcStatus = http.StatusOK
	}
	if opts.vpcBody == "" {
		opts.vpcBody = "vpc-0abc12345"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get(awsHdrTokenTTL) == "" {
			http.Error(w, "missing ttl header", http.StatusBadRequest)
			return
		}
		w.WriteHeader(opts.tokenStatus)
		_, _ = w.Write([]byte(opts.tokenBody))
	})

	tokenCheck := func(w http.ResponseWriter, r *http.Request) bool {
		if opts.requireToken && r.Header.Get(awsHdrToken) == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		if !tokenCheck(w, r) {
			return
		}
		w.WriteHeader(opts.documentStatus)
		_, _ = w.Write([]byte(opts.documentBody))
	})
	mux.HandleFunc("/latest/meta-data/mac", func(w http.ResponseWriter, r *http.Request) {
		if !tokenCheck(w, r) {
			return
		}
		w.WriteHeader(opts.macStatus)
		_, _ = w.Write([]byte(opts.macBody))
	})
	mux.HandleFunc("/latest/meta-data/network/interfaces/macs/", func(w http.ResponseWriter, r *http.Request) {
		if !tokenCheck(w, r) {
			return
		}
		w.WriteHeader(opts.vpcStatus)
		_, _ = w.Write([]byte(opts.vpcBody))
	})

	return httptest.NewServer(mux)
}

func TestAWS_Fetch_HappyPath(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{requireToken: true})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	checks := map[string]string{
		"Provider":         ProviderAWS,
		"InstanceID":       "i-0123456789abcdef0",
		"Region":           "us-east-1",
		"AvailabilityZone": "us-east-1a",
		"InstanceType":     "t3.micro",
		"AccountID":        "123456789012",
		"NetworkID":        "vpc-0abc12345",
	}
	got := map[string]string{
		"Provider":         meta.Provider,
		"InstanceID":       meta.InstanceID,
		"Region":           meta.Region,
		"AvailabilityZone": meta.AvailabilityZone,
		"InstanceType":     meta.InstanceType,
		"AccountID":        meta.AccountID,
		"NetworkID":        meta.NetworkID,
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func TestAWS_Probe_TokenSucceeds(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	if !p.Probe(context.Background()) {
		t.Error("Probe returned false on healthy IMDS")
	}
}

func TestAWS_Probe_Token401(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{tokenStatus: http.StatusUnauthorized})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	if p.Probe(context.Background()) {
		t.Error("Probe returned true despite token 401")
	}
}

func TestAWS_Probe_Unreachable(t *testing.T) {
	// 169.254.169.255 is link-local but no listener — connection refused on Linux,
	// or timeout. Probe must return false either way and respect ctx budget.
	p := NewAWSWithBase("http://127.0.0.1:1") // port 1 reserved → ECONNREFUSED fast
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if p.Probe(ctx) {
		t.Error("Probe returned true when nothing listening")
	}
}

func TestAWS_Fetch_TokenFailure(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{tokenStatus: http.StatusUnauthorized})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when token fetch fails")
	}
}

func TestAWS_Fetch_DocumentError_StillReturnsProvider(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{documentStatus: http.StatusInternalServerError})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected document error to surface")
	}
	if meta == nil || meta.Provider != ProviderAWS {
		t.Errorf("expected partial meta with Provider=aws, got %+v", meta)
	}
}

func TestAWS_Fetch_DocumentParseError(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{documentBody: "{ not json"})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected parse error to surface")
	}
}

func TestAWS_Fetch_VPCMissing_StillPopulatesDocFields(t *testing.T) {
	server := newAWSMockServer(t, awsMockOpts{
		vpcStatus: http.StatusNotFound,
		vpcBody:   "not found",
	})
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta.InstanceID == "" {
		t.Error("InstanceID should be populated even without vpc-id")
	}
	if meta.NetworkID != "" {
		t.Errorf("NetworkID should be empty on 404, got %q", meta.NetworkID)
	}
}

func TestAWS_Fetch_MACEmpty_NoVPCAttempt(t *testing.T) {
	var vpcHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("TOKEN"))
	})
	mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, _ *http.Request) {
		doc := awsIdentityDocument{InstanceID: "i-x", Region: "us-east-1"}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/latest/meta-data/mac", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("")) // empty MAC
	})
	mux.HandleFunc("/latest/meta-data/network/interfaces/macs/", func(_ http.ResponseWriter, _ *http.Request) {
		vpcHits.Add(1)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	meta, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta.NetworkID != "" {
		t.Errorf("NetworkID should be empty when MAC is empty, got %q", meta.NetworkID)
	}
	if vpcHits.Load() != 0 {
		t.Errorf("expected zero vpc-id hits when MAC empty, got %d", vpcHits.Load())
	}
}

func TestAWS_Fetch_RespectsContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("TOKEN"))
	}))
	defer server.Close()

	p := NewAWSWithBase(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := p.Fetch(ctx)
	if err == nil {
		t.Error("expected ctx-deadline error")
	}
}
