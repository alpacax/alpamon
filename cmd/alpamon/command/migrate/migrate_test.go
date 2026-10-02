package migrate

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripGeneratedSuffix(t *testing.T) {
	cases := map[string]string{
		"mybox-a3f9c1":                 "mybox",
		"prod-web-1-deadbe":            "prod-web-1",
		"production-web-server-abcdef": "production-web-server",
		"mybox":                        "mybox",               // no suffix
		"mybox-AB":                     "mybox-AB",            // wrong length
		"mybox-zzzzzz":                 "mybox-zzzzzz",        // non-hex
		"mybox-a3f9c1-deadbe":          "mybox-a3f9c1",        // strips only the trailing hex suffix
		"mybox-deadbe-xyz789":          "mybox-deadbe-xyz789", // trailing non-hex blocks strip
	}
	for in, want := range cases {
		assert.Equal(t, want, stripGeneratedSuffix(in), "stripGeneratedSuffix(%q)", in)
	}
}

func TestFetchCurrentName_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/api/servers/servers/srv-xyz/"), "unexpected path: %s", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), `id="srv-xyz"`, "auth header missing id")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "production-web-deadbe",
		})
	}))
	defer srv.Close()

	sslVerify = false
	caCert = ""

	got, err := fetchCurrentName(t.Context(), &config.ServerConfig{
		URL: srv.URL, ID: "srv-xyz", Key: "key-xyz",
	})
	require.NoError(t, err)
	require.Equal(t, "production-web-deadbe", got)
}

func TestFetchCurrentName_404SurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"not found"}`))
	}))
	defer srv.Close()

	sslVerify = false
	caCert = ""

	_, err := fetchCurrentName(t.Context(), &config.ServerConfig{
		URL: srv.URL, ID: "srv-xyz", Key: "key-xyz",
	})
	require.ErrorContains(t, err, "status 404", "error should mention status")
}

func TestNormalizeURL_TrailingSlashAndWhitespace(t *testing.T) {
	cases := map[string]string{
		"https://a.example.com/":  "https://a.example.com",
		"  https://a.example.com": "https://a.example.com",
		"https://a.example.com":   "https://a.example.com",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeURL(in), "normalizeURL(%q)", in)
	}
}

func TestNormalizeHostname_StripsFQDNDomain(t *testing.T) {
	require.Equal(t, "host", normalizeHostname("host.example.com"))
	require.Equal(t, "plain", normalizeHostname("plain"))
}

func TestBuildConfContent_IncludesAllFields(t *testing.T) {
	out, err := buildConfContent("https://b.example.com", "srv-1", "key-1", true, "/etc/ssl/ca.pem")
	require.NoError(t, err)
	for _, want := range []string{
		"url = https://b.example.com",
		"id = srv-1",
		"key = key-1",
		"verify = true",
		"ca_cert = /etc/ssl/ca.pem",
		"debug = false",
	} {
		assert.Contains(t, out, want, "expected %q in conf output", want)
	}
}

func TestBuildConfContent_OmitsCACertWhenEmpty(t *testing.T) {
	out, err := buildConfContent("https://b.example.com", "srv-1", "key-1", false, "")
	require.NoError(t, err)
	require.NotContains(t, out, "ca_cert", "expected ca_cert to be omitted")
	require.Contains(t, out, "verify = false")
}

func TestRegisterOnTarget_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/servers/servers/register/", r.URL.Path)
		got := r.Header.Get("Authorization")
		assert.True(t, strings.HasPrefix(got, `token="`), "unexpected auth header: %q", got)
		var req registerRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req), "decode req")
		assert.NotEmpty(t, req.Name, "bad request body: %+v", req)
		assert.NotEmpty(t, req.Platform, "bad request body: %+v", req)
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
	require.NoError(t, err)
	require.Equal(t, "srv-new", resp.ID, "unexpected response: %+v", resp)
	require.Equal(t, "key-new", resp.Key, "unexpected response: %+v", resp)
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
	require.ErrorContains(t, err, "status 403", "error should mention status code")
}

func TestRegisterOnTarget_PlanLimit(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantSubstrs []string
		wantAbsent  []string
	}{
		{
			name: "new envelope with gate, axis and next",
			body: `{"code":"server_limit_exceeded","gate":"plan","axis":"server",` +
				`"next":"/api/workspaces/workspaces/9/entitlements/","hint":"xyz123-should-not-leak"}`,
			wantSubstrs: []string{
				"plan limit reached: servers.",
				"If this host was registered before, delete the old server entry first, then retry",
				// httptest's URL is 127.0.0.1:<port>, never a managed
				// "<label>.<region>.alpacon.io" host, so this exercises the
				// self-hosted words fallback end to end.
				"Upgrade: Settings → Billing in your Alpacon console.",
				"Talk to us: https://www.alpacax.com/alpacon/pricing",
			},
			wantAbsent: []string{"xyz123-should-not-leak", "{", "\"code\""},
		},
		{
			name: "old-server gate-less body (code only, no gate/axis/next)",
			body: `{"code":"server_limit_exceeded"}`,
			wantSubstrs: []string{
				"plan limit reached: servers.",
				"If this host was registered before, delete the old server entry first, then retry",
			},
			wantAbsent: []string{"{", "\"code\""},
		},
		{
			name: "non-JSON body renders the generic fallback",
			body: `<html>upstream says xyz123-should-not-leak</html>`,
			wantSubstrs: []string{
				"plan limit reached.",
				"Upgrade: Settings → Billing in your Alpacon console.",
				"Talk to us: https://www.alpacax.com/alpacon/pricing",
			},
			wantAbsent: []string{"xyz123-should-not-leak", "<html>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusPaymentRequired)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			newURL = srv.URL
			apiToken = "test-token"
			serverName = "my-host"
			platform = "debian"
			sslVerify = false

			_, err := registerOnTarget(t.Context())
			require.Error(t, err)
			for _, s := range tt.wantSubstrs {
				assert.Contains(t, err.Error(), s)
			}
			for _, s := range tt.wantAbsent {
				assert.NotContains(t, err.Error(), s, "message must not echo the raw response body")
			}
		})
	}
}

func TestCleanupTargetRegistration_CallsUnregisterEndpoint(t *testing.T) {
	called := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Contains(t, r.URL.Path, "/api/servers/servers/srv-xyz/unregister/")
		assert.Contains(t, r.Header.Get("Authorization"), `id="srv-xyz"`, "auth header missing id")
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

	require.Len(t, called, 1, "expected unregister endpoint to be hit")
}

// A detection failure must name the distribution instead of defaulting the write-once platform value.
func TestResolvePlatform_DetectionFailurePropagates(t *testing.T) {
	origPlatform := platform
	origDetect := detectPlatformFn
	t.Cleanup(func() { platform = origPlatform; detectPlatformFn = origDetect })

	platform = ""
	detectPlatformFn = func() (string, error) {
		return "", errors.New("unrecognized Linux distribution \"arch\"")
	}

	_, err := resolvePlatform()
	require.Error(t, err, "expected resolvePlatform to fail when platform detection fails")
	assert.ErrorContains(t, err, "arch", "error must name the distribution")
}

// The override and validation matrix is host-dependent and lives in utils.TestResolveServerPlatform.
func TestResolvePlatform_UsesDetectionSeam(t *testing.T) {
	origPlatform := platform
	origDetect := detectPlatformFn
	t.Cleanup(func() { platform = origPlatform; detectPlatformFn = origDetect })

	platform = ""
	detectPlatformFn = func() (string, error) { return "rhel", nil }

	got, err := resolvePlatform()
	require.NoError(t, err)
	assert.Equal(t, "rhel", got, "expected the detected platform")
}
