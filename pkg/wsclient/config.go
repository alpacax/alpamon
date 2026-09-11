package wsclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/gorilla/websocket"
)

// Defaults applied to zero-valued Config fields.
const (
	// DefaultHandshakeTimeout bounds the opening handshake in DefaultDialer.
	DefaultHandshakeTimeout = 30 * time.Second

	// DefaultReadTimeout is how long a read may wait for a frame before the
	// connection is treated as dead. The Alpacon backhaul pings well inside it.
	DefaultReadTimeout = 35 * time.Minute

	// DefaultWriteTimeout bounds each write, so a stalled peer cannot hold up
	// every other writer.
	DefaultWriteTimeout = 10 * time.Second

	// DefaultReadLimit is the largest inbound frame accepted, in bytes.
	DefaultReadLimit = 10 << 20

	// DefaultMinBackoff and DefaultMaxBackoff bound the reconnect schedule.
	DefaultMinBackoff = 5 * time.Second
	DefaultMaxBackoff = 60 * time.Second
)

// Config is what a caller injects to build a Client or Dial. Only URL, ID and
// Key are required; every other zero value means the documented default.
type Config struct {
	// URL is the full endpoint, e.g. wss://backhaul.example.com/ws/servers/backhaul/.
	// http and https are accepted and mapped to ws and wss.
	URL string

	// ID and Key are sent as Authorization: id="<ID>", key="<Key>".
	ID  string
	Key string

	// Origin, when non-empty, is sent as the Origin header.
	Origin string

	// UserAgent is sent as the User-Agent header. Empty means
	// "alpamon/<version>", which is only right for alpamon itself: any other
	// agent should name itself here.
	UserAgent string

	// Header carries extra request headers. Authorization and User-Agent
	// always come from the fields above, as does Origin when it is set.
	Header http.Header

	// Dialer opens the connection. Nil means DefaultDialer(). A non-nil
	// dialer is used as given, so start from DefaultDialer() to keep its
	// handshake timeout and proxy settings.
	Dialer *websocket.Dialer

	// ReadLimit is the largest inbound frame accepted, in bytes. Zero means
	// DefaultReadLimit; a negative value removes the limit.
	ReadLimit int64

	// ReadTimeout is re-armed before every read. Zero means DefaultReadTimeout.
	ReadTimeout time.Duration

	// WriteTimeout bounds every write. Zero means DefaultWriteTimeout.
	WriteTimeout time.Duration

	// MinBackoff and MaxBackoff bound the wait between reconnect attempts.
	// Each wait is the doubling base times a random factor in [0.5, 1.5),
	// clamped to this range. Zero means DefaultMinBackoff and DefaultMaxBackoff.
	MinBackoff time.Duration
	MaxBackoff time.Duration

	// Rand returns the value in [0, 1) the jitter factor is drawn from. Nil
	// means math/rand/v2. Tests pin it for a deterministic schedule.
	Rand func() float64

	// OnConnect runs after every successful dial. OnDisconnect runs once for
	// every connection that OnConnect announced; err is nil when the client
	// closed a healthy connection because Shutdown, Reconnect or the Run
	// context asked it to, and is otherwise what ended the connection: a
	// failed read or write, the peer's close, or the handler's error. OnRetry
	// runs before each wait between connection attempts, whether the last dial
	// failed or a connection ended before it proved itself; err is what caused
	// the wait, and attempt counts from 1, restarting after a connection that
	// worked. All three run on the Run goroutine, so a slow hook delays
	// reading and reconnecting. They may call any Client method except Run.
	OnConnect    func()
	OnDisconnect func(err error)
	OnRetry      func(attempt int, delay time.Duration, err error)
}

// DefaultDialer returns the dialer a nil Config.Dialer stands for: a
// DefaultHandshakeTimeout handshake, the proxy named by HTTPS_PROXY,
// HTTP_PROXY and NO_PROXY, and the system roots for TLS. Each call returns a
// new dialer, which the caller may adjust before putting it in a Config.
func DefaultDialer() *websocket.Dialer {
	return &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: DefaultHandshakeTimeout,
	}
}

// reservedHeaders are the request headers gorilla/websocket sets itself and
// refuses to take from the caller. Rejecting them up front keeps a config
// mistake from turning into a dial that fails, and retries, forever.
var reservedHeaders = []string{
	"Upgrade",
	"Connection",
	"Sec-Websocket-Key",
	"Sec-Websocket-Version",
	"Sec-Websocket-Extensions",
}

// dialSettings is the validated part of a Config that opening a connection
// needs. Dial uses only this.
type dialSettings struct {
	url       string
	header    http.Header
	dialer    *websocket.Dialer
	readLimit int64
}

// settings is a fully validated Config with every default applied.
type settings struct {
	dialSettings

	readTimeout  time.Duration
	writeTimeout time.Duration
	minBackoff   time.Duration
	maxBackoff   time.Duration
	rand         func() float64

	onConnect    func()
	onDisconnect func(error)
	onRetry      func(int, time.Duration, error)
}

func (c Config) dialSettings() (dialSettings, error) {
	u, err := normalizeURL(c.URL)
	if err != nil {
		return dialSettings{}, err
	}
	if err := checkCredential("ID", c.ID); err != nil {
		return dialSettings{}, err
	}
	if err := checkCredential("Key", c.Key); err != nil {
		return dialSettings{}, err
	}

	header := make(http.Header, len(c.Header)+3)
	for k, vs := range c.Header {
		ck := http.CanonicalHeaderKey(k)
		header[ck] = append(header[ck], vs...)
	}
	for _, k := range reservedHeaders {
		if _, ok := header[k]; ok {
			return dialSettings{}, fmt.Errorf("wsclient: header %s is set by the websocket handshake and cannot be overridden", k)
		}
	}
	header.Set("Authorization", fmt.Sprintf(`id="%s", key="%s"`, c.ID, c.Key))
	if c.Origin != "" {
		header.Set("Origin", c.Origin)
	}
	userAgent := c.UserAgent
	if userAgent == "" {
		userAgent = "alpamon/" + version.Version
	}
	header.Set("User-Agent", userAgent)

	var dialer *websocket.Dialer
	if c.Dialer == nil {
		dialer = DefaultDialer()
	} else {
		copied := *c.Dialer // later edits to the caller's dialer must not reach a running client
		dialer = &copied
	}

	readLimit := c.ReadLimit
	switch {
	case readLimit == 0:
		readLimit = DefaultReadLimit
	case readLimit < 0:
		readLimit = 0 // gorilla/websocket reads zero as no limit
	}

	// gorilla/websocket refuses this pair as well, and refuses it at dial
	// time, where a Client would retry the same doomed handshake forever.
	if _, ok := header["Sec-Websocket-Protocol"]; ok && len(dialer.Subprotocols) > 0 {
		return dialSettings{}, errors.New("wsclient: set the subprotocol in Dialer.Subprotocols or in Header, not both")
	}

	return dialSettings{url: u, header: header, dialer: dialer, readLimit: readLimit}, nil
}

func (c Config) resolve() (settings, error) {
	ds, err := c.dialSettings()
	if err != nil {
		return settings{}, err
	}

	s := settings{
		dialSettings: ds,
		readTimeout:  c.ReadTimeout,
		writeTimeout: c.WriteTimeout,
		minBackoff:   c.MinBackoff,
		maxBackoff:   c.MaxBackoff,
		rand:         c.Rand,
		onConnect:    c.OnConnect,
		onDisconnect: c.OnDisconnect,
		onRetry:      c.OnRetry,
	}

	for _, d := range []struct {
		name  string
		value *time.Duration
		def   time.Duration
	}{
		{"ReadTimeout", &s.readTimeout, DefaultReadTimeout},
		{"WriteTimeout", &s.writeTimeout, DefaultWriteTimeout},
		{"MinBackoff", &s.minBackoff, DefaultMinBackoff},
		{"MaxBackoff", &s.maxBackoff, DefaultMaxBackoff},
	} {
		switch {
		case *d.value < 0:
			return settings{}, fmt.Errorf("wsclient: %s must not be negative, got %s", d.name, *d.value)
		case *d.value == 0:
			*d.value = d.def
		}
	}
	if s.minBackoff > s.maxBackoff {
		return settings{}, fmt.Errorf("wsclient: MinBackoff %s exceeds MaxBackoff %s", s.minBackoff, s.maxBackoff)
	}

	if s.onConnect == nil {
		s.onConnect = func() {}
	}
	if s.onDisconnect == nil {
		s.onDisconnect = func(error) {}
	}
	if s.onRetry == nil {
		s.onRetry = func(int, time.Duration, error) {}
	}
	return s, nil
}

// normalizeURL checks that raw names a websocket endpoint and maps http and
// https onto ws and wss, the only schemes gorilla/websocket dials.
func normalizeURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("wsclient: URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error repeats the whole URL, which may carry a token; keep only the cause.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return "", fmt.Errorf("wsclient: invalid URL: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "ws", "http":
		u.Scheme = "ws"
	case "wss", "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("wsclient: URL scheme %q is not one of ws, wss, http or https", u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("wsclient: URL must not carry credentials; use ID and Key")
	}
	if u.Host == "" {
		return "", errors.New("wsclient: URL has no host")
	}
	return u.String(), nil
}

// checkCredential rejects a value that would corrupt the Authorization header:
// the backhaul parses it with id="([^"]+)", so a quote would silently cut the
// value short.
func checkCredential(name, value string) error {
	if value == "" {
		return fmt.Errorf("wsclient: %s is required", name)
	}
	if strings.ContainsAny(value, "\"\r\n") {
		return fmt.Errorf("wsclient: %s must not contain quotes or line breaks", name)
	}
	return nil
}
