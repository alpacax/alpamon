package register

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alpacax/alpamon/pkg/cloud"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterRequest_TagsSerialization(t *testing.T) {
	tests := []struct {
		name             string
		tags             map[string]string
		expectTagsInJSON bool
		expectedTags     map[string]string
	}{
		{
			name:             "nil tags omitted from JSON",
			tags:             nil,
			expectTagsInJSON: false,
		},
		{
			name:             "single tag",
			tags:             map[string]string{"env": "prod"},
			expectTagsInJSON: true,
			expectedTags:     map[string]string{"env": "prod"},
		},
		{
			name:             "multiple tags",
			tags:             map[string]string{"env": "prod", "role": "web", "team": "platform"},
			expectTagsInJSON: true,
			expectedTags:     map[string]string{"env": "prod", "role": "web", "team": "platform"},
		},
		{
			name:             "tag with empty value",
			tags:             map[string]string{"env": ""},
			expectTagsInJSON: true,
			expectedTags:     map[string]string{"env": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RegisterRequest{
				Name:     "test-server",
				Platform: "debian",
				Tags:     tt.tags,
			}

			data, err := json.Marshal(req)
			require.NoError(t, err)

			var raw map[string]json.RawMessage
			err = json.Unmarshal(data, &raw)
			require.NoError(t, err)

			if tt.expectTagsInJSON {
				assert.Contains(t, raw, "tags")

				var parsedTags map[string]string
				err = json.Unmarshal(raw["tags"], &parsedTags)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedTags, parsedTags)
			} else {
				_, hasTags := raw["tags"]
				assert.False(t, hasTags, "JSON should not contain 'tags' field")
			}
		})
	}
}

func TestSendRegisterRequest_WithTags(t *testing.T) {
	tests := []struct {
		name       string
		tags       map[string]string
		expectTags bool
	}{
		{
			name:       "request with tags",
			tags:       map[string]string{"env": "prod", "role": "web"},
			expectTags: true,
		},
		{
			name:       "request without tags",
			tags:       nil,
			expectTags: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyCh := make(chan RegisterRequest, 1)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				assert.Contains(t, r.Header.Get("Authorization"), "token=")

				var body RegisterRequest
				err := json.NewDecoder(r.Body).Decode(&body)
				assert.NoError(t, err)
				bodyCh <- body

				w.WriteHeader(http.StatusCreated)
				resp := RegisterResponse{
					ID:   "test-id",
					Key:  "test-key",
					Name: "test-server",
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			oldServerURL, oldAPIToken, oldSSLVerify := serverURL, apiToken, sslVerify
			t.Cleanup(func() {
				serverURL = oldServerURL
				apiToken = oldAPIToken
				sslVerify = oldSSLVerify
			})

			serverURL = server.URL
			apiToken = "test-token"
			sslVerify = true

			req := RegisterRequest{
				Name:     "test-server",
				Platform: "debian",
				Tags:     tt.tags,
			}

			resp, err := sendRegisterRequest(req)
			require.NoError(t, err)
			assert.Equal(t, "test-id", resp.ID)
			assert.Equal(t, "test-key", resp.Key)

			receivedBody := <-bodyCh
			if tt.expectTags {
				assert.Equal(t, tt.tags, receivedBody.Tags)
			} else {
				assert.Nil(t, receivedBody.Tags)
			}
		})
	}
}

func TestSendRegisterRequest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid request"}`))
	}))
	defer server.Close()

	oldServerURL, oldAPIToken, oldSSLVerify := serverURL, apiToken, sslVerify
	t.Cleanup(func() {
		serverURL = oldServerURL
		apiToken = oldAPIToken
		sslVerify = oldSSLVerify
	})

	serverURL = server.URL
	apiToken = "test-token"
	sslVerify = true

	req := RegisterRequest{
		Name:     "test-server",
		Platform: "debian",
		Tags:     map[string]string{"env": "prod"},
	}

	resp, err := sendRegisterRequest(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "registration failed (status 400)")
}

func TestHostnameFQDNStripping(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		expected string
	}{
		{
			name:     "FQDN is stripped to short hostname",
			hostname: "host.example.com",
			expected: "host",
		},
		{
			name:     "short hostname unchanged",
			hostname: "myserver",
			expected: "myserver",
		},
		{
			name:     "hostname with subdomain stripped",
			hostname: "web01.dc1.example.com",
			expected: "web01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeHostname(tt.hostname))
		})
	}
}

func TestMergeCloudAndUserTags(t *testing.T) {
	tests := []struct {
		name string
		auto map[string]string
		user map[string]string
		want map[string]string
	}{
		{
			name: "both nil returns nil",
			auto: nil,
			user: nil,
			want: nil,
		},
		{
			name: "user only",
			auto: nil,
			user: map[string]string{"env": "prod"},
			want: map[string]string{"env": "prod"},
		},
		{
			name: "auto only",
			auto: map[string]string{"cloud:provider": "aws", "cloud:instance_id": "i-1"},
			user: nil,
			want: map[string]string{"cloud:provider": "aws", "cloud:instance_id": "i-1"},
		},
		{
			name: "user wins on key conflict",
			auto: map[string]string{"cloud:provider": "aws", "cloud:instance_id": "i-1"},
			user: map[string]string{"cloud:provider": "manual-override", "env": "prod"},
			want: map[string]string{
				"cloud:provider":    "manual-override",
				"cloud:instance_id": "i-1",
				"env":               "prod",
			},
		},
		{
			name: "disjoint keys merge cleanly",
			auto: map[string]string{"cloud:region": "us-east-1"},
			user: map[string]string{"role": "web"},
			want: map[string]string{
				"cloud:region": "us-east-1",
				"role":         "web",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeCloudAndUserTags(tt.auto, tt.user)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetectCloudTags_NoProviderReturnsNil(t *testing.T) {
	old := detectCloud
	t.Cleanup(func() { detectCloud = old; noCloudProbe = false })

	detectCloud = func(_ context.Context) (*cloud.Metadata, error) {
		return nil, cloud.ErrNoCloudProvider
	}
	noCloudProbe = false

	if got := detectCloudTags(); got != nil {
		t.Errorf("detectCloudTags() = %v, want nil", got)
	}
}

func TestDetectCloudTags_HappyPathReturnsTags(t *testing.T) {
	old := detectCloud
	t.Cleanup(func() { detectCloud = old; noCloudProbe = false })

	detectCloud = func(_ context.Context) (*cloud.Metadata, error) {
		return &cloud.Metadata{
			Provider:   cloud.ProviderAWS,
			InstanceID: "i-x",
			Region:     "us-east-1",
		}, nil
	}
	noCloudProbe = false

	got := detectCloudTags()
	assert.Equal(t, cloud.ProviderAWS, got[cloud.TagProvider])
	assert.Equal(t, "i-x", got[cloud.TagInstanceID])
	assert.Equal(t, "us-east-1", got[cloud.TagRegion])
}

func TestDetectCloudTags_NoCloudProbeFlagSkipsDetection(t *testing.T) {
	old := detectCloud
	t.Cleanup(func() { detectCloud = old; noCloudProbe = false })

	called := false
	detectCloud = func(_ context.Context) (*cloud.Metadata, error) {
		called = true
		return nil, nil
	}
	noCloudProbe = true

	if got := detectCloudTags(); got != nil {
		t.Errorf("detectCloudTags() with --no-cloud-probe should return nil, got %v", got)
	}
	if called {
		t.Error("detectCloud must not run when --no-cloud-probe is set")
	}
}

func TestDetectCloudTags_NonGracefulErrorDoesNotFail(t *testing.T) {
	old := detectCloud
	t.Cleanup(func() { detectCloud = old; noCloudProbe = false })

	detectCloud = func(_ context.Context) (*cloud.Metadata, error) {
		return nil, errors.New("imds gateway timeout")
	}
	noCloudProbe = false

	if got := detectCloudTags(); got != nil {
		t.Errorf("detectCloudTags() should return nil on unexpected errors, got %v", got)
	}
}

func TestDetectCloudTags_PartialMetadataReturnsAvailableTags(t *testing.T) {
	// cloud.Detect now returns (partialMeta, fetchErr) when Probe succeeds but
	// Fetch errors mid-read. detectCloudTags must use whatever tags we have
	// rather than dropping them on the floor.
	old := detectCloud
	t.Cleanup(func() { detectCloud = old; noCloudProbe = false })

	detectCloud = func(_ context.Context) (*cloud.Metadata, error) {
		return &cloud.Metadata{
			Provider: cloud.ProviderAWS,
			Region:   "us-east-1",
			// InstanceID intentionally absent — partial detection
		}, errors.New("imds document 500")
	}
	noCloudProbe = false

	got := detectCloudTags()
	assert.Equal(t, cloud.ProviderAWS, got[cloud.TagProvider])
	assert.Equal(t, "us-east-1", got[cloud.TagRegion])
	_, hasInstanceID := got[cloud.TagInstanceID]
	assert.False(t, hasInstanceID, "partial detection should not include empty cloud:instance_id")
}

func TestTagFlagParsing(t *testing.T) {
	tests := []struct {
		name         string
		flagArgs     []string
		expectedTags map[string]string
	}{
		{
			name:         "single tag",
			flagArgs:     []string{"--tag", "env=prod"},
			expectedTags: map[string]string{"env": "prod"},
		},
		{
			name:         "multiple tags",
			flagArgs:     []string{"--tag", "env=prod", "--tag", "role=web"},
			expectedTags: map[string]string{"env": "prod", "role": "web"},
		},
		{
			name:         "comma-separated tags",
			flagArgs:     []string{"--tag", "env=prod,role=web"},
			expectedTags: map[string]string{"env": "prod", "role": "web"},
		},
		{
			name:         "no tags",
			flagArgs:     []string{},
			expectedTags: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parsedTags map[string]string

			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			fs.StringToStringVar(&parsedTags, "tag", nil, "Server tags")

			err := fs.Parse(tt.flagArgs)
			require.NoError(t, err)

			if tt.expectedTags == nil {
				assert.Nil(t, parsedTags)
			} else {
				assert.Equal(t, tt.expectedTags, parsedTags)
			}
		})
	}
}
