package utils

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsServerURL(t *testing.T) {
	server, err := url.Parse("https://console.example.com:8443")
	require.NoError(t, err)

	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "https://console.example.com:8443/api/", want: true},
		{raw: "https://CONSOLE.example.com:8443/api/", want: true},
		{raw: "https://console.example.com/api/", want: false},
		{raw: "https://console.example.com:9443/api/", want: false},
		{raw: "http://console.example.com:8443/api/", want: false},
		{raw: "https://files.console.example.com:8443/api/", want: false},
		{raw: "https://other.example.com:8443/api/", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.want, IsServerURL(u, server))
		})
	}
}

func TestServerOnlyAuthorization(t *testing.T) {
	server, err := url.Parse("https://console.example.com")
	require.NoError(t, err)
	check := ServerOnlyAuthorization(server)

	tests := []struct {
		name     string
		dest     string
		wantAuth bool
	}{
		{name: "same server keeps the key", dest: "https://console.example.com/api/next/", wantAuth: true},
		{name: "another port drops the key", dest: "https://console.example.com:8443/api/", wantAuth: false},
		{name: "subdomain drops the key", dest: "https://files.console.example.com/api/", wantAuth: false},
		{name: "plain http drops the key", dest: "http://console.example.com/api/", wantAuth: false},
		{name: "other host drops the key", dest: "https://other.example.com/api/", wantAuth: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.dest, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "key")

			require.NoError(t, check(req, []*http.Request{{}}))
			assert.Equal(t, tc.wantAuth, req.Header.Get("Authorization") != "")
		})
	}

	t.Run("stops after 10 redirects", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://console.example.com/", nil)
		require.NoError(t, err)
		assert.Error(t, check(req, make([]*http.Request, 10)))
	})
}

func TestOriginOnlyAuthorization(t *testing.T) {
	origin, err := http.NewRequest(http.MethodGet, "https://console.example.com/api/", nil)
	require.NoError(t, err)

	tests := []struct {
		dest     string
		wantAuth bool
	}{
		{dest: "https://console.example.com/api/next/", wantAuth: true},
		{dest: "https://console.example.com:8443/api/", wantAuth: false},
		{dest: "http://console.example.com/api/", wantAuth: false},
	}
	for _, tc := range tests {
		t.Run(tc.dest, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.dest, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "key")

			require.NoError(t, OriginOnlyAuthorization(req, []*http.Request{origin}))
			assert.Equal(t, tc.wantAuth, req.Header.Get("Authorization") != "")
		})
	}

	req, err := http.NewRequest(http.MethodGet, "https://console.example.com/", nil)
	require.NoError(t, err)
	via := make([]*http.Request, 10)
	via[0] = origin
	assert.Error(t, OriginOnlyAuthorization(req, via))
}
