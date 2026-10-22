package runner

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTunnelDialer_HonorsTheProxyEnvironment(t *testing.T) {
	dialer := newTunnelDialer()
	require.NotNil(t, dialer.Proxy)
	assert.Equal(t, reflect.ValueOf(http.ProxyFromEnvironment).Pointer(), reflect.ValueOf(dialer.Proxy).Pointer())
}
