package wsclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{URL: "wss://backhaul.example.com/ws/servers/backhaul/", ID: "srv-1", Key: "secret"}
}

func TestNormalizeURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"http://example.com/ws/", "ws://example.com/ws/"},
		{"https://example.com/ws/", "wss://example.com/ws/"},
		{"HTTPS://example.com:8443/ws/?a=1", "wss://example.com:8443/ws/?a=1"},
		{"ws://127.0.0.1:8081/ws/", "ws://127.0.0.1:8081/ws/"},
		{"wss://example.com/ws/", "wss://example.com/ws/"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := normalizeURL(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizeURL_Rejects(t *testing.T) {
	for _, tc := range []struct {
		in, wantErr string
	}{
		{"", "URL is required"},
		{"ftp://example.com/", `scheme "ftp"`},
		{"example.com/ws/", `scheme ""`},
		{"wss:///ws/", "no host"},
		{"wss://user:pass@example.com/ws/", "must not carry credentials"},
		{"wss://exa mple.com/ws/", "invalid URL"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			_, err := normalizeURL(tc.in)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestNormalizeURL_ParseErrorHidesTheURL matters because an endpoint URL can
// carry a token in its query, and the error is going to end up in a log.
func TestNormalizeURL_ParseErrorHidesTheURL(t *testing.T) {
	_, err := normalizeURL("wss://exa mple.com/ws/?token=hunter2")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")
}

func TestResolve_AppliesDefaults(t *testing.T) {
	s, err := validConfig().resolve()
	require.NoError(t, err)

	assert.Equal(t, DefaultReadTimeout, s.readTimeout)
	assert.Equal(t, DefaultWriteTimeout, s.writeTimeout)
	assert.Equal(t, DefaultMinBackoff, s.minBackoff)
	assert.Equal(t, DefaultMaxBackoff, s.maxBackoff)
	assert.Equal(t, int64(DefaultReadLimit), s.readLimit)
	assert.Equal(t, DefaultHandshakeTimeout, s.dialer.HandshakeTimeout)
	assert.NotNil(t, s.dialer.Proxy, "the default dialer must honor the proxy environment")
	assert.NotNil(t, s.onConnect)
	assert.NotNil(t, s.onDisconnect)
	assert.NotNil(t, s.onRetry)
}

func TestResolve_KeepsExplicitValues(t *testing.T) {
	cfg := validConfig()
	cfg.ReadTimeout = time.Minute
	cfg.WriteTimeout = 2 * time.Second
	cfg.MinBackoff = time.Second
	cfg.MaxBackoff = 16 * time.Minute
	cfg.ReadLimit = 4096

	s, err := cfg.resolve()
	require.NoError(t, err)

	assert.Equal(t, time.Minute, s.readTimeout)
	assert.Equal(t, 2*time.Second, s.writeTimeout)
	assert.Equal(t, time.Second, s.minBackoff)
	assert.Equal(t, 16*time.Minute, s.maxBackoff)
	assert.Equal(t, int64(4096), s.readLimit)
}

func TestResolve_NegativeReadLimitMeansUnlimited(t *testing.T) {
	cfg := validConfig()
	cfg.ReadLimit = -1

	s, err := cfg.resolve()
	require.NoError(t, err)
	assert.Zero(t, s.readLimit, "gorilla/websocket reads a zero limit as none")
}

func TestResolve_Rejects(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"missing ID":                 {func(c *Config) { c.ID = "" }, "ID is required"},
		"missing Key":                {func(c *Config) { c.Key = "" }, "Key is required"},
		"quote in ID":                {func(c *Config) { c.ID = `a"b` }, "ID must not contain quotes"},
		"line break in Key":          {func(c *Config) { c.Key = "a\r\nX-Evil: 1" }, "Key must not contain quotes or line breaks"},
		"negative ReadTimeout":       {func(c *Config) { c.ReadTimeout = -time.Second }, "ReadTimeout must not be negative"},
		"negative WriteTimeout":      {func(c *Config) { c.WriteTimeout = -time.Second }, "WriteTimeout must not be negative"},
		"negative MinBackoff":        {func(c *Config) { c.MinBackoff = -time.Second }, "MinBackoff must not be negative"},
		"negative MaxBackoff":        {func(c *Config) { c.MaxBackoff = -time.Second }, "MaxBackoff must not be negative"},
		"min above max":              {func(c *Config) { c.MinBackoff, c.MaxBackoff = time.Minute, time.Second }, "exceeds MaxBackoff"},
		"min above the default max":  {func(c *Config) { c.MinBackoff = 2 * DefaultMaxBackoff }, "exceeds MaxBackoff"},
		"reserved header":            {func(c *Config) { c.Header = http.Header{"Upgrade": {"h2c"}} }, "Upgrade is set by the websocket handshake"},
		"reserved header, lowercase": {func(c *Config) { c.Header = http.Header{"sec-websocket-key": {"x"}} }, "Sec-Websocket-Key is set by the websocket handshake"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			_, err := cfg.resolve()
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestResolve_RejectsASubprotocolSetTwice covers the other pair
// gorilla/websocket refuses at dial time, which a Client would otherwise
// retry forever.
func TestResolve_RejectsASubprotocolSetTwice(t *testing.T) {
	cfg := validConfig()
	cfg.Header = http.Header{"Sec-WebSocket-Protocol": {"alpacon.v1"}}
	cfg.Dialer = DefaultDialer()
	cfg.Dialer.Subprotocols = []string{"alpacon.v1"}

	_, err := cfg.resolve()

	assert.ErrorContains(t, err, "not both")
}

func TestResolve_AllowsASubprotocolInOnePlace(t *testing.T) {
	for name, set := range map[string]func(*Config){
		"in Header": func(c *Config) { c.Header = http.Header{"Sec-WebSocket-Protocol": {"alpacon.v1"}} },
		"in Dialer": func(c *Config) {
			c.Dialer = DefaultDialer()
			c.Dialer.Subprotocols = []string{"alpacon.v1"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			set(&cfg)
			_, err := cfg.resolve()
			assert.NoError(t, err)
		})
	}
}

func TestResolve_Header(t *testing.T) {
	cfg := validConfig()
	cfg.Origin = "https://alpacon.example.com"
	cfg.UserAgent = "alpamon-kube/0.1.0"
	cfg.Header = http.Header{
		"x-cluster-id":  {"c-1"},
		"Authorization": {"Bearer should-lose"},
		"User-Agent":    {"should-lose"},
	}

	s, err := cfg.resolve()
	require.NoError(t, err)

	assert.Equal(t, `id="srv-1", key="secret"`, s.header.Get("Authorization"), "the exact format the backhaul parses")
	assert.Equal(t, "https://alpacon.example.com", s.header.Get("Origin"))
	assert.Equal(t, "alpamon-kube/0.1.0", s.header.Get("User-Agent"))
	assert.Equal(t, "c-1", s.header.Get("X-Cluster-Id"), "extra headers pass through, canonicalized")
	assert.Len(t, s.header.Values("Authorization"), 1, "the caller's Authorization must be replaced, not appended to")
}

func TestResolve_HeaderDefaults(t *testing.T) {
	cfg := validConfig()
	cfg.Header = http.Header{"Origin": {"https://from-header.example.com"}}

	s, err := cfg.resolve()
	require.NoError(t, err)

	assert.Equal(t, "alpamon/"+version.Version, s.header.Get("User-Agent"))
	assert.Equal(t, "https://from-header.example.com", s.header.Get("Origin"), "an empty Origin field leaves the caller's header alone")
}

func TestResolve_DoesNotAliasCallerState(t *testing.T) {
	extra := http.Header{"X-Trace": {"a"}}
	dialer := &websocket.Dialer{HandshakeTimeout: time.Second, Subprotocols: []string{"alpacon.v1"}}
	cfg := validConfig()
	cfg.Header = extra
	cfg.Dialer = dialer

	s, err := cfg.resolve()
	require.NoError(t, err)

	extra["X-Trace"][0] = "changed"
	extra.Set("X-Late", "late")
	dialer.HandshakeTimeout = time.Hour
	dialer.Subprotocols[0] = "changed"

	assert.Equal(t, "a", s.header.Get("X-Trace"), "the caller's header slices must be copied")
	assert.Empty(t, s.header.Get("X-Late"))
	assert.Equal(t, time.Second, s.dialer.HandshakeTimeout, "a running client must not see later edits to the caller's dialer")
	assert.Equal(t, []string{"alpacon.v1"}, s.dialer.Subprotocols, "the shallow copy shares this slice's array, so it has to be cloned")
}

// TestResolve_BoundsACallerDialersHandshake covers the obvious thing to
// write, &websocket.Dialer{}: gorilla stops watching the context once the
// socket is up, so a zero handshake timeout leaves a peer that accepts TCP
// and never answers able to wedge the client with no signal at all.
func TestResolve_BoundsACallerDialersHandshake(t *testing.T) {
	cfg := validConfig()
	cfg.Dialer = &websocket.Dialer{}

	s, err := cfg.resolve()
	require.NoError(t, err)
	assert.Equal(t, DefaultHandshakeTimeout, s.dialer.HandshakeTimeout)

	cfg.Dialer = &websocket.Dialer{HandshakeTimeout: time.Second}
	s, err = cfg.resolve()
	require.NoError(t, err)
	assert.Equal(t, time.Second, s.dialer.HandshakeTimeout, "an explicit timeout is left alone")
}

// TestResolve_ClonesTheTLSConfig matters because gorilla reads
// TLSClientConfig again on every dial: a caller that shares one tls.Config
// with something else and later sets InsecureSkipVerify on it would
// otherwise turn off certificate verification for the next reconnect.
func TestResolve_ClonesTheTLSConfig(t *testing.T) {
	shared := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := validConfig()
	cfg.Dialer = &websocket.Dialer{TLSClientConfig: shared}

	s, err := cfg.resolve()
	require.NoError(t, err)

	shared.InsecureSkipVerify = true

	assert.False(t, s.dialer.TLSClientConfig.InsecureSkipVerify,
		"a running client must not start skipping verification because the caller edited its tls.Config")
}

// TestDefaults_AreTheValuesTheyClaim pins the constants themselves. Asserting
// that the resolver assigns DefaultReadTimeout only proves the wiring; a typo
// in the constant would ship green.
func TestDefaults_AreTheValuesTheyClaim(t *testing.T) {
	assert.Equal(t, 30*time.Second, DefaultHandshakeTimeout)
	assert.Equal(t, 35*time.Minute, DefaultReadTimeout)
	assert.Equal(t, 10*time.Second, DefaultWriteTimeout)
	assert.Equal(t, int64(10<<20), int64(DefaultReadLimit))
	assert.Equal(t, 5*time.Second, DefaultMinBackoff)
	assert.Equal(t, 60*time.Second, DefaultMaxBackoff)
}

func TestNew_RejectsAnInvalidConfig(t *testing.T) {
	c, err := New(Config{})
	assert.Nil(t, c, "New must not hand back a half-built client")
	assert.ErrorContains(t, err, "URL is required")
}

func TestDefaultDialer_ReturnsAFreshDialer(t *testing.T) {
	a, b := DefaultDialer(), DefaultDialer()
	a.HandshakeTimeout = time.Hour
	assert.Equal(t, DefaultHandshakeTimeout, b.HandshakeTimeout)
}
