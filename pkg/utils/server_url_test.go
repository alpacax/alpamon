package utils

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveServerURL(t *testing.T) {
	server, err := url.Parse("https://console.example.com:8443/base")
	require.NoError(t, err)

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "path-only joins the server host", raw: "/ws/channel/abc/", want: "wss://console.example.com:8443/ws/channel/abc/"},
		{name: "path-only keeps the query", raw: "/ws/channel/abc/?token=t1", want: "wss://console.example.com:8443/ws/channel/abc/?token=t1"},
		{name: "path-only keeps escaped segments", raw: "/files/a%2Fb", want: "wss://console.example.com:8443/files/a%2Fb"},
		{name: "path-only drops the fragment", raw: "/ws/channel/abc/#frag", want: "wss://console.example.com:8443/ws/channel/abc/"},
		{name: "absolute URL returned as parsed", raw: "ws://other.example.com/ws/", want: "ws://other.example.com/ws/"},
		{name: "scheme-relative refused", raw: "//other.example.com/ws/", wantErr: "scheme-relative"},
		{name: "triple slash refused", raw: "///ws/", wantErr: "scheme-relative"},
		{name: "relative path refused", raw: "ws/channel/", wantErr: "must start with /"},
		{name: "host without scheme refused", raw: "console.example.com/ws/", wantErr: "must start with /"},
		{name: "empty refused", raw: "", wantErr: "must start with /"},
		{name: "userinfo refused", raw: "wss://user:pass@console.example.com/ws/", wantErr: "userinfo"},
		{name: "backslash refused", raw: "/ws\\channel/", wantErr: "backslash"},
		{name: "backslash in host refused", raw: "wss://console.example.com\\@other.example.com/ws/", wantErr: "backslash"},
		{name: "absolute URL without host refused", raw: "wss:/ws/channel/", wantErr: "has no host"},
		{name: "absolute URL with only a port refused", raw: "wss://:443/ws/channel/", wantErr: "has no host"},
		{name: "unparsable URL refused", raw: "/ws/\x7f", wantErr: "does not parse"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveServerURL(tc.raw, server, "wss")
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}

func TestResolveServerURL_PathOnlyNeedsServerHost(t *testing.T) {
	_, err := ResolveServerURL("/ws/channel/", &url.URL{}, "wss")
	require.ErrorContains(t, err, "no server host")

	_, err = ResolveServerURL("/ws/channel/", nil, "wss")
	require.ErrorContains(t, err, "no server host")

	_, err = ResolveServerURL("/ws/channel/", &url.URL{Scheme: "https", Host: ":443"}, "wss")
	require.ErrorContains(t, err, "no server host")
}

func TestResolveServerURL_ErrorsOmitTheURL(t *testing.T) {
	server := &url.URL{Scheme: "https", Host: "console.example.com"}
	for _, raw := range []string{"//h/secret-token", "secret-token", "wss://u@h/secret-token", "/secret-token\\", "/secret-token\x7f"} {
		_, err := ResolveServerURL(raw, server, "wss")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret-token")
	}
}
