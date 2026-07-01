package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeServerConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "alpamon.conf")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestReadServer_Valid(t *testing.T) {
	p := writeServerConf(t, "[server]\nurl = https://alpacon.example.com\nid = srv-1\nkey = k-1\n")
	s, err := ReadServer(p)
	require.NoError(t, err)
	assert.Equal(t, "https://alpacon.example.com", s.URL)
	assert.Equal(t, "srv-1", s.ID)
	assert.Equal(t, "k-1", s.Key)
}

func TestReadServer_TrimsWhitespace(t *testing.T) {
	p := writeServerConf(t, "[server]\nurl =   https://x   \nid =  abc \nkey = def\n")
	s, err := ReadServer(p)
	require.NoError(t, err)
	assert.Equal(t, "https://x", s.URL)
	assert.Equal(t, "abc", s.ID)
}

func TestReadServer_Errors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing [server] section", body: "[other]\nx = 1\n"},
		{name: "missing url", body: "[server]\nid = abc\nkey = def\n"},
		{name: "missing id", body: "[server]\nurl = https://x\nkey = def\n"},
		{name: "missing key", body: "[server]\nurl = https://x\nid = abc\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadServer(writeServerConf(t, tt.body))
			assert.Error(t, err)
		})
	}
}

func TestReadServer_NonexistentFile(t *testing.T) {
	_, err := ReadServer(filepath.Join(t.TempDir(), "does-not-exist.conf"))
	assert.Error(t, err)
}

func TestRenderConf_RoundTripsThroughReadServer(t *testing.T) {
	out, err := RenderConf(ServerConfig{URL: "https://x.example.com", ID: "srv-1", Key: "k-1"}, true, "/etc/ssl/ca.pem")
	require.NoError(t, err)
	for _, want := range []string{
		"url = https://x.example.com",
		"id = srv-1",
		"key = k-1",
		"verify = true",
		"ca_cert = /etc/ssl/ca.pem",
		"debug = false",
	} {
		assert.Contains(t, out, want)
	}

	// What RenderConf writes, ReadServer must parse back identically.
	got, err := ReadServer(writeServerConf(t, out))
	require.NoError(t, err)
	assert.Equal(t, "https://x.example.com", got.URL)
	assert.Equal(t, "srv-1", got.ID)
	assert.Equal(t, "k-1", got.Key)
}

func TestRenderConf_OmitsCACertWhenEmpty(t *testing.T) {
	out, err := RenderConf(ServerConfig{URL: "https://x", ID: "a", Key: "b"}, false, "")
	require.NoError(t, err)
	assert.NotContains(t, out, "ca_cert")
	assert.Contains(t, out, "verify = false")
}
