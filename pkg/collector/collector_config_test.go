package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	session "github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchConfig_DecodesTheServersLowercaseKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, confURL, r.URL.Path)
		_, _ = w.Write([]byte(`[{"type":"cpu","interval":60},{"type":"memory","interval":30}]`))
	}))
	t.Cleanup(srv.Close)
	s := &session.Session{BaseURL: srv.URL, Client: srv.Client()}

	conf, err := fetchConfig(s)

	require.NoError(t, err)
	assert.Equal(t, []collectConf{{Type: base.CPU, Interval: 60}, {Type: base.Mem, Interval: 30}}, conf)
}
