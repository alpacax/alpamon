package runner

import (
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTunnelDialer_HonorsTheProxyEnvironment(t *testing.T) {
	dialer := newTunnelDialer()
	require.NotNil(t, dialer.Proxy)
	assert.Equal(t, reflect.ValueOf(utils.WebsocketProxy).Pointer(), reflect.ValueOf(dialer.Proxy).Pointer())
}

const wsDialerChild = "ALPAMON_TEST_WS_DIALER_CHILD"

// TestWebsocketDialer_HTTPSProxyDialsDirectly covers a proxy scheme gorilla
// cannot dial through: the dialer must go direct, as it did before it read
// the proxy environment, rather than fail every WebSocket connection. Go reads
// the proxy environment once per process, so it runs in a fresh one.
func TestWebsocketDialer_HTTPSProxyDialsDirectly(t *testing.T) {
	if os.Getenv(wsDialerChild) != "" {
		var logs bytes.Buffer
		log.Logger = zerolog.New(&logs)
		req, err := http.NewRequest(http.MethodGet, "https://alpacon.example.test/ws/servers/backhaul/", nil)
		require.NoError(t, err)

		dialer := newTunnelDialer()
		for range 2 {
			proxyURL, err := dialer.Proxy(req)
			require.NoError(t, err)
			assert.Nil(t, proxyURL)
		}
		assert.Equal(t, 1, strings.Count(logs.String(), `"level":"warn"`), logs.String())
		assert.NotContains(t, logs.String(), "secret")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWebsocketDialer_HTTPSProxyDialsDirectly$", "-test.count=1")
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "REQUEST_METHOD":
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, wsDialerChild+"=1", "HTTPS_PROXY=https://user:secret@proxy.example:3128")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
}
