package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/host"
)

var (
	PlatformLike string
	pattern      = regexp.MustCompile(`[^\w@%+=:,./-]`)
)

func InitPlatform() {
	getPlatformLike()
}

func getPlatformLike() {
	system := runtime.GOOS

	switch system {
	case "darwin":
		PlatformLike = system
	case "linux":
		platformInfo, err := host.Info()
		if err != nil {
			log.Error().Err(err).Msg("Failed to retrieve platform information.")
			os.Exit(1)
		}
		switch platformInfo.Platform {
		case "ubuntu", "debian", "raspbian":
			PlatformLike = "debian"
		case "centos", "rhel", "redhat", "amazon", "amzn", "fedora", "rocky", "oracle", "ol":
			PlatformLike = "rhel"
		default:
			log.Fatal().Msgf("Platform %s not supported.", platformInfo.Platform)
		}
	case "windows":
		PlatformLike = "windows"
	default:
		log.Fatal().Msgf("Unsupported os: %s.", runtime.GOOS)
	}
}

// SetPlatformLike allows setting PlatformLike for testing purposes.
func SetPlatformLike(platform string) {
	PlatformLike = platform
}

func JoinPath(base string, paths ...string) string {
	fullURL, err := url.JoinPath(base, paths...)
	if err != nil {
		log.Error().Err(err).Msg("Failed to join path.")
		return ""
	}

	return fullURL
}

func IsSuccessStatusCode(code int) bool {
	return code/100 == 2
}

// ScanBlock is a utility function that can be used to scan through text files
// that chunk using two-lined separators.
//
// Based on a function from the Datadog Agent.
// Original source: https://github.com/DataDog/datadog-agent
// License: Apache-2.0 license
func ScanBlock(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return i + 2, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func GetEnvOrDefault(envVar, defaultValue string) string {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}
	return value
}

func Quote(s string) string {
	if len(s) == 0 {
		return "''"
	}

	if pattern.MatchString(s) {
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}

	return s
}

func GetSystemUser(username string) (*user.User, error) {
	currentUID := os.Getuid()

	// If Alpamon is not running as root or username is not specified, use the current user
	if currentUID != 0 || username == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to get current user: %w", err)
		}
		return usr, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup specified user: %w", err)
	}
	return usr, nil
}

// GetLatestVersion returns the latest alpamon release tag from GitHub, or ""
// on any failure. proxyURL, when non-empty, routes only this request through
// the given proxy so closed-network deployments can reach GitHub without
// touching the agent's process environment or control-plane connection.
func GetLatestVersion(proxyURL string) string {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/alpacax/alpamon/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", GetUserAgent("alpamon"))

	client := NewVersionLookupClient(proxyURL)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return ""
	}
	return release.TagName
}

// NewVersionLookupClient builds the HTTP client for the GitHub version lookup.
// With an empty proxyURL it uses the default transport, which respects the
// process-level proxy environment when present. With a proxyURL it uses a
// per-request transport pinned to that proxy, so the payload-provided proxy
// never leaks into the agent's process globals.
func NewVersionLookupClient(proxyURL string) *http.Client {
	client := &http.Client{Timeout: 10 * time.Second}
	if proxyURL == "" {
		return client
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil || parsed.Host == "" {
		log.Warn().Str("proxy", proxyURL).Msg("Invalid package proxy URL; using default transport for version lookup.")
		return client
	}
	// Clone the default transport so its settings (timeouts, TLS, HTTP/2)
	// carry over, instead of a bare &http.Transport{} that also leaks its
	// keep-alive connections. Safe assertion: instrumentation may swap
	// http.DefaultTransport for a different RoundTripper.
	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.Proxy = http.ProxyURL(parsed)
	client.Transport = transport
	return client
}

func GetUserAgent(name string) string {
	return fmt.Sprintf("%s/%s", name, version.Version)
}

func LookUpUID(username string) (int, error) {
	if username == "" {
		return -1, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(usr.Uid)
}

func LookUpGID(groupname string) (int, error) {
	if groupname == "" {
		return -1, nil
	}

	group, err := user.LookupGroup(groupname)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(group.Gid)
}
