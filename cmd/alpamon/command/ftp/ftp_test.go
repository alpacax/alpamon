package ftp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseWorkerArgs(t *testing.T, args []string, stdin io.Reader) (runner.FtpConfigData, error) {
	t.Helper()
	cmd := newFtpCmd()
	require.NoError(t, cmd.ParseFlags(args))
	positional := cmd.Flags().Args()
	require.NoError(t, cmd.ValidateArgs(positional))
	return configData(cmd, positional, stdin)
}

// testCertPEM returns a self-signed certificate in PEM form.
func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestConfigData_VerifiesByDefault(t *testing.T) {
	data, err := parseWorkerArgs(t, []string{"wss://console.example.com/ws/ftp/", "https://console.example.com", "/home/u"}, strings.NewReader("ignored"))
	require.NoError(t, err)

	assert.Equal(t, "wss://console.example.com/ws/ftp/", data.URL)
	assert.Equal(t, "https://console.example.com", data.ServerURL)
	assert.Equal(t, "/home/u", data.HomeDirectory)
	assert.False(t, data.SkipSSLVerify)
	assert.Empty(t, data.CaCertPEM)
}

func TestConfigData_ReadsWhatTheAgentPasses(t *testing.T) {
	cert := testCertPEM(t)
	// A bundle over 128 KiB, the most one environment string can hold on Linux.
	bundle := bytes.Repeat(cert, 128*1024/len(cert)+1)
	require.Greater(t, len(bundle), 128*1024)

	tests := []struct {
		name      string
		sslVerify bool
		caPEM     []byte
	}{
		{name: "verification on", sslVerify: true},
		{name: "verification off", sslVerify: false},
		{name: "configured CA", sslVerify: true, caPEM: cert},
		{name: "CA bundle over 128 KiB", sslVerify: true, caPEM: bundle},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := runner.FtpWorkerArgs("wss://console.example.com/ws/ftp/", "https://console.example.com", "-home", tc.sslVerify, tc.caPEM != nil)
			require.Equal(t, "ftp", args[0])

			data, err := parseWorkerArgs(t, args[1:], bytes.NewReader(tc.caPEM))
			require.NoError(t, err)
			assert.Equal(t, "wss://console.example.com/ws/ftp/", data.URL)
			assert.Equal(t, "https://console.example.com", data.ServerURL)
			assert.Equal(t, "-home", data.HomeDirectory)
			assert.Equal(t, !tc.sslVerify, data.SkipSSLVerify)
			assert.Equal(t, tc.caPEM, data.CaCertPEM)
		})
	}
}

func TestConfigData_RefusesABadCAOnStdin(t *testing.T) {
	tests := []struct {
		name    string
		stdin   []byte
		wantErr string
	}{
		{name: "empty", stdin: nil, wantErr: "no CA certificate"},
		{name: "over the cap", stdin: make([]byte, runner.MaxFtpCACertSize+1), wantErr: "larger than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := runner.FtpWorkerArgs("wss://console.example.com/ws/ftp/", "https://console.example.com", "/home/u", true, true)
			_, err := parseWorkerArgs(t, args[1:], bytes.NewReader(tc.stdin))
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}
