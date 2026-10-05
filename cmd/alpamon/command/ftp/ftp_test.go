package ftp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseWorkerArgs(t *testing.T, args []string) runner.FtpConfigData {
	t.Helper()
	cmd := newFtpCmd()
	require.NoError(t, cmd.ParseFlags(args))
	positional := cmd.Flags().Args()
	require.NoError(t, cmd.ValidateArgs(positional))
	return configData(cmd, positional)
}

// unsetCAEnv clears the CA variable for the test and restores it afterwards.
func unsetCAEnv(t *testing.T) {
	t.Helper()
	t.Setenv(runner.FtpCaCertEnv, "")
	require.NoError(t, os.Unsetenv(runner.FtpCaCertEnv))
}

func TestConfigData_VerifiesByDefault(t *testing.T) {
	unsetCAEnv(t)
	data := parseWorkerArgs(t, []string{"wss://console.example.com/ws/ftp/", "https://console.example.com", "/home/u"})

	assert.Equal(t, "wss://console.example.com/ws/ftp/", data.URL)
	assert.Equal(t, "https://console.example.com", data.ServerURL)
	assert.Equal(t, "/home/u", data.HomeDirectory)
	assert.False(t, data.SkipSSLVerify)
	assert.Empty(t, data.CaCertPEM)
}

func TestConfigData_ReadsWhatTheAgentPasses(t *testing.T) {
	caPEM := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(caPEM), 0o600))

	tests := []struct {
		name      string
		sslVerify bool
		caCert    string
		wantPEM   string
	}{
		{name: "verification on", sslVerify: true},
		{name: "verification off", sslVerify: false},
		{name: "configured CA", sslVerify: true, caCert: caPath, wantPEM: caPEM},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unsetCAEnv(t)
			env, err := runner.FtpWorkerEnv(tc.caCert)
			require.NoError(t, err)
			for _, kv := range env {
				name, value, ok := strings.Cut(kv, "=")
				require.True(t, ok)
				t.Setenv(name, value)
			}

			args := runner.FtpWorkerArgs("wss://console.example.com/ws/ftp/", "https://console.example.com", "-home", tc.sslVerify)
			require.Equal(t, "ftp", args[0])

			data := parseWorkerArgs(t, args[1:])
			assert.Equal(t, "wss://console.example.com/ws/ftp/", data.URL)
			assert.Equal(t, "https://console.example.com", data.ServerURL)
			assert.Equal(t, "-home", data.HomeDirectory)
			assert.Equal(t, !tc.sslVerify, data.SkipSSLVerify)
			assert.Equal(t, tc.wantPEM, string(data.CaCertPEM))
		})
	}
}
