package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCurrentServer_FindsAllFields(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "alpamon.conf")
	body := `[server]
url = https://workspace-a.example.com
id = abc
key = secret

[ssl]
verify = true
`
	if err := os.WriteFile(conf, []byte(body), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readCurrentServer(conf)
	if err != nil {
		t.Fatalf("readCurrentServer: %v", err)
	}
	if got.URL != "https://workspace-a.example.com" || got.ID != "abc" || got.Key != "secret" {
		t.Fatalf("got %+v", got)
	}
}

func TestReadCurrentServer_MissingURL(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "alpamon.conf")
	if err := os.WriteFile(conf, []byte("[server]\nid=abc\nkey=k\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readCurrentServer(conf); err == nil {
		t.Fatalf("expected error on missing url, got nil")
	}
}

func TestReadCurrentServer_MissingIDKey(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "alpamon.conf")
	if err := os.WriteFile(conf, []byte("[server]\nurl=https://a\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readCurrentServer(conf); err == nil {
		t.Fatalf("expected error on missing id/key, got nil")
	}
}

func TestStripGeneratedSuffix(t *testing.T) {
	cases := map[string]string{
		"mybox-a3f9c1":                 "mybox",
		"prod-web-1-deadbe":            "prod-web-1",
		"production-web-server-abcdef": "production-web-server",
		"mybox":                        "mybox",                    // no suffix
		"mybox-AB":                     "mybox-AB",                 // wrong length
		"mybox-zzzzzz":                 "mybox-zzzzzz",             // non-hex
		"mybox-a3f9c1-deadbe":          "mybox-a3f9c1",             // strips only the trailing hex suffix
		"mybox-deadbe-xyz789":          "mybox-deadbe-xyz789",      // trailing non-hex blocks strip
	}
	for in, want := range cases {
		if got := stripGeneratedSuffix(in); got != want {
			t.Errorf("stripGeneratedSuffix(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestFetchCurrentName_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/servers/servers/srv-xyz/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.Contains(got, `id="srv-xyz"`) {
			t.Errorf("auth header missing id: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "production-web-deadbe",
		})
	}))
	defer srv.Close()

	sslVerify = false
	caCert = ""

	got, err := fetchCurrentName(t.Context(), &currentServer{
		URL: srv.URL, ID: "srv-xyz", Key: "key-xyz",
	})
	if err != nil {
		t.Fatalf("fetchCurrentName: %v", err)
	}
	if got != "production-web-deadbe" {
		t.Fatalf("got %q", got)
	}
}

func TestFetchCurrentName_404SurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"not found"}`))
	}))
	defer srv.Close()

	sslVerify = false
	caCert = ""

	_, err := fetchCurrentName(t.Context(), &currentServer{
		URL: srv.URL, ID: "srv-xyz", Key: "key-xyz",
	})
	if err == nil {
		t.Fatalf("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("error should mention status, got: %v", err)
	}
}

func TestNormalizeURL_TrailingSlashAndWhitespace(t *testing.T) {
	cases := map[string]string{
		"https://a.example.com/":  "https://a.example.com",
		"  https://a.example.com": "https://a.example.com",
		"https://a.example.com":   "https://a.example.com",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestNormalizeHostname_StripsFQDNDomain(t *testing.T) {
	if got := normalizeHostname("host.example.com"); got != "host" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeHostname("plain"); got != "plain" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildConfContent_IncludesAllFields(t *testing.T) {
	out, err := buildConfContent("https://b.example.com", "srv-1", "key-1", true, "/etc/ssl/ca.pem")
	if err != nil {
		t.Fatalf("buildConfContent: %v", err)
	}
	for _, want := range []string{
		"url = https://b.example.com",
		"id = srv-1",
		"key = key-1",
		"verify = true",
		"ca_cert = /etc/ssl/ca.pem",
		"debug = false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in conf output, got:\n%s", want, out)
		}
	}
}

func TestBuildConfContent_OmitsCACertWhenEmpty(t *testing.T) {
	out, err := buildConfContent("https://b.example.com", "srv-1", "key-1", false, "")
	if err != nil {
		t.Fatalf("buildConfContent: %v", err)
	}
	if strings.Contains(out, "ca_cert") {
		t.Fatalf("expected ca_cert to be omitted, got:\n%s", out)
	}
	if !strings.Contains(out, "verify = false") {
		t.Fatalf("expected verify = false, got:\n%s", out)
	}
}

func TestRegisterOnTarget_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/servers/servers/register/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, `token="`) {
			t.Errorf("unexpected auth header: %q", got)
		}
		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode req: %v", err)
		}
		if req.Name == "" || req.Platform == "" {
			t.Errorf("bad request body: %+v", req)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registerResponse{
			ID: "srv-new", Key: "key-new", Name: req.Name,
		})
	}))
	defer srv.Close()

	// Configure package globals to point at the mock server.
	newURL = srv.URL
	apiToken = "test-token"
	serverName = "my-host"
	platform = "debian"
	sslVerify = false
	caCert = ""

	resp, err := registerOnTarget(t.Context())
	if err != nil {
		t.Fatalf("registerOnTarget: %v", err)
	}
	if resp.ID != "srv-new" || resp.Key != "key-new" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRegisterOnTarget_SurfacesNon2xxStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"invalid token"}`))
	}))
	defer srv.Close()

	newURL = srv.URL
	apiToken = "bad-token"
	serverName = "my-host"
	platform = "debian"
	sslVerify = false

	_, err := registerOnTarget(t.Context())
	if err == nil {
		t.Fatalf("expected error on 403, got nil")
	}
	if !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("error should mention status code, got: %v", err)
	}
}

func TestCleanupTargetRegistration_CallsUnregisterEndpoint(t *testing.T) {
	called := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/api/servers/servers/srv-xyz/unregister/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.Contains(got, `id="srv-xyz"`) {
			t.Errorf("auth header missing id: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
		select {
		case called <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	newURL = srv.URL
	sslVerify = false
	caCert = ""

	cleanupTargetRegistration("srv-xyz", "key-xyz")

	select {
	case <-called:
	default:
		t.Fatalf("expected unregister endpoint to be hit")
	}
}
