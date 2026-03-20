package register

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
			hostname := tt.hostname
			if idx := strings.Index(hostname, "."); idx > 0 {
				hostname = hostname[:idx]
			}
			assert.Equal(t, tt.expected, hostname)
		})
	}
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
