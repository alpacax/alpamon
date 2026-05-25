package register

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/cloud"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/spf13/cobra"
)

var (
	configPath = filepath.Join(utils.ConfigDir(), "alpamon.conf")
	logPath    = filepath.Join(utils.LogDir(), "alpamon.log")
)

var (
	serverURL    string
	apiToken     string
	serverName   string
	platform     string
	sslVerify    bool
	caCert       string
	tags         map[string]string
	noCloudProbe bool

	// detectCloud is overridable in tests to inject a stub detector. Production
	// uses cloud.Detect with the default provider list.
	detectCloud = func(ctx context.Context) (*cloud.Metadata, error) {
		_, meta, err := cloud.Detect(ctx, cloud.DefaultProviders())
		return meta, err
	}
)

// registerCloudDetectTimeout caps the synchronous cloud probe at register time
// so a non-cloud host (where all probes time out) still finishes registration
// within a reasonable budget.
const registerCloudDetectTimeout = 5 * time.Second

// RegisterRequest represents the request body for server registration
type RegisterRequest struct {
	Name     string            `json:"name"`
	Platform string            `json:"platform"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// RegisterResponse represents the response from server registration
type RegisterResponse struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// RegisterCmd represents the register command
var RegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register this server with Alpacon",
	Long: `Register this server with Alpacon.
Requires an API token with servers:register scope.
Groups are automatically assigned from the token's allowed_groups configuration.

On cloud hosts (AWS / GCP / Azure), alpamon probes the link-local IMDS to
auto-detect provider metadata (instance_id, region, instance_type, ...) and
includes the results as cloud:* tags. Operator-supplied --tag flags override
auto-detected values on key conflicts. Pass --no-cloud-probe to skip detection.

Examples:
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN>
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN> --name my-server
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN> --tag env=prod --tag role=web
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN> --no-cloud-probe

Options:
  --url             Alpacon server URL (required)
  --token           API token (servers:register scope required)
  --name            Server name (optional, defaults to hostname)
  --platform        Platform (debian/rhel, auto-detect if omitted)
  --ssl-verify      SSL certificate verification (default: true)
  --ca-cert         CA certificate path
  --tag             Server tags in key=value format (repeatable, or comma-separated: "k1=v1,k2=v2")
  --no-cloud-probe  Skip cloud metadata IMDS probe`,
	RunE: runRegister,
}

func init() {
	RegisterCmd.Flags().StringVar(&serverURL, "url", "", "Alpacon server URL (required)")
	RegisterCmd.Flags().StringVar(&apiToken, "token", "", "API token (servers:register scope required)")
	RegisterCmd.Flags().StringVar(&serverName, "name", "", "Server name (optional, defaults to hostname)")
	RegisterCmd.Flags().StringVar(&platform, "platform", "", "Platform (debian/rhel, auto-detect)")
	RegisterCmd.Flags().BoolVar(&sslVerify, "ssl-verify", true, "SSL certificate verification")
	RegisterCmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path")
	RegisterCmd.Flags().StringToStringVar(&tags, "tag", nil, "Server tags in key=value format (repeatable, or comma-separated: \"k1=v1,k2=v2\")")
	RegisterCmd.Flags().BoolVar(&noCloudProbe, "no-cloud-probe", false, "Skip cloud metadata IMDS probe at registration")

	_ = RegisterCmd.MarkFlagRequired("url")
	_ = RegisterCmd.MarkFlagRequired("token")
}

func runRegister(cmd *cobra.Command, args []string) error {
	// 0. On Windows, place the binary in %ProgramFiles%\alpamon and
	// re-exec from there so the Service Manager entry we're about to
	// create points at a stable path. No-op on Linux/macOS, where
	// apt/brew already handled placement.
	if relaunched, err := ensureInstalled(); err != nil {
		return err
	} else if relaunched {
		return nil
	}

	// 1. Check if config file already exists (prevent re-registration)
	if info, err := os.Stat(configPath); err == nil {
		if info.Size() > 0 {
			return fmt.Errorf("config file already exists: %s\nServer is already registered. To re-register, first unregister this server from the Alpacon console, then delete the config file and run register again", configPath)
		}
		// Empty config file exists (likely created by systemd-tmpfiles) — will be cleaned up during registration
		fmt.Printf("Note: Empty config file found at %s, will be overwritten\n", configPath)
	}

	// 2. Auto-detect server name from hostname if not provided
	if serverName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		serverName = normalizeHostname(hostname)
		fmt.Printf("Server name auto-detected: %s\n", serverName)
	}

	// 3. Auto-detect platform
	if platform == "" {
		platform = detectPlatform()
		fmt.Printf("Platform auto-detected: %s\n", platform)
	}

	// 4. Auto-detect cloud provider metadata (best-effort) and merge with
	// operator-supplied --tag flags. User-supplied tags win over auto-detected
	// values so an operator can override a misdetection (e.g. forcing
	// `--tag cloud:provider=aws` on a host where IMDS is restricted).
	finalTags := mergeCloudAndUserTags(detectCloudTags(cmd.Context()), tags)

	// 5. Create registration request body
	reqBody := RegisterRequest{
		Name:     serverName,
		Platform: platform,
		Tags:     finalTags,
	}

	fmt.Printf("Registering server: %s\n", serverURL)

	// 6. API call
	resp, err := sendRegisterRequest(reqBody)
	if err != nil {
		return err
	}

	// 7. Create config file
	if err := writeConfigFile(resp); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	// 8. Create required directories
	if err := ensureDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// 9. Start service
	fmt.Println("\nStarting alpamon service...")
	if err := startService(); err != nil {
		fmt.Printf("Warning: Failed to start service: %v\n", err)
		printManualStartHint()
	}

	// 10. Success message
	fmt.Printf("\n==========================================\n")
	fmt.Printf("Server registered successfully!\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("  Name: %s\n", resp.Name)
	fmt.Printf("  ID:   %s\n", resp.ID)
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("==========================================\n")

	return nil
}

// detectCloudTags runs the IMDS probe and returns the cloud:* tag set, or nil
// when no provider responds / when the operator passed --no-cloud-probe.
//
// The parent ctx comes from cmd.Context() so a future signal-aware
// RootCmd.ExecuteContext (e.g. wrapping with signal.NotifyContext) will
// propagate Ctrl-C / SIGTERM into the IMDS probe without further changes here.
//
// cloud.Detect can return four shapes:
//   - (nil, nil, ErrNoCloudProvider): on-prem / dev path → no tags, log normal
//   - (provider, fullMeta, nil): happy path → use tags, log instance
//   - (provider, partialMeta, fetchErr): IMDS partially answered → use whatever
//     tags we have, log degraded
//   - (nil, nil, other err): unrecoverable detection error (incl. ctx
//     cancel/deadline) → no tags, log error
//
// Surfacing the partial case (rather than throwing away meta on err != nil)
// matters because the partial tags still help reconcile when at least the
// provider name was captured.
func detectCloudTags(parent context.Context) map[string]string {
	if noCloudProbe {
		fmt.Println("Cloud detection skipped (--no-cloud-probe).")
		return nil
	}

	ctx, cancel := context.WithTimeout(parent, registerCloudDetectTimeout)
	defer cancel()

	meta, err := detectCloud(ctx)
	if errors.Is(err, cloud.ErrNoCloudProvider) {
		fmt.Println("No cloud provider detected; registering as plain server.")
		return nil
	}
	if err != nil && meta == nil {
		fmt.Printf("Cloud detection error: %v (continuing without cloud tags)\n", err)
		return nil
	}
	if meta == nil {
		return nil
	}
	tags := meta.ToTags()
	if len(tags) == 0 {
		return nil
	}

	switch {
	case err != nil:
		fmt.Printf("Cloud detected (partial) for %s: %v\n", meta.Provider, err)
	case meta.InstanceID != "":
		fmt.Printf("Cloud detected: %s (instance=%s)\n", meta.Provider, meta.InstanceID)
	default:
		fmt.Printf("Cloud detected: %s\n", meta.Provider)
	}
	return tags
}

// mergeCloudAndUserTags returns a single map combining auto-detected tags with
// operator-supplied --tag flags. User-supplied tags win on key conflicts so
// the operator can override a misdetection.
func mergeCloudAndUserTags(auto, user map[string]string) map[string]string {
	if len(auto) == 0 && len(user) == 0 {
		return nil
	}
	out := make(map[string]string, len(auto)+len(user))
	for k, v := range auto {
		out[k] = v
	}
	for k, v := range user {
		out[k] = v
	}
	return out
}

// normalizeHostname strips the domain part from FQDN hostnames
// (e.g., "host.example.com" → "host").
func normalizeHostname(hostname string) string {
	if idx := strings.Index(hostname, "."); idx > 0 {
		return hostname[:idx]
	}
	return hostname
}

func detectPlatform() string {
	hostInfo, err := host.Info()
	if err != nil {
		fmt.Println("Warning: Failed to detect platform, defaulting to debian")
		return "debian"
	}

	if runtime.GOOS == "windows" {
		return "windows"
	}

	switch hostInfo.Platform {
	case "darwin":
		return "darwin"
	case "ubuntu", "debian", "raspbian":
		return "debian"
	case "centos", "rhel", "redhat", "amazon", "amzn", "fedora", "rocky", "oracle", "ol":
		return "rhel"
	default:
		// Check if platform name contains known keywords
		platformLower := strings.ToLower(hostInfo.Platform)
		if strings.Contains(platformLower, "ubuntu") ||
			strings.Contains(platformLower, "debian") {
			return "debian"
		}
		if strings.Contains(platformLower, "centos") ||
			strings.Contains(platformLower, "rhel") ||
			strings.Contains(platformLower, "fedora") ||
			strings.Contains(platformLower, "rocky") {
			return "rhel"
		}
		return "debian" // default fallback
	}
}

func sendRegisterRequest(req RegisterRequest) (*RegisterResponse, error) {
	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	url := fmt.Sprintf("%s/api/servers/servers/register/", strings.TrimSuffix(serverURL, "/"))
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf(`token="%s"`, apiToken))
	httpReq.Header.Set("Content-Type", "application/json")

	client, err := createHTTPClient()
	if err != nil {
		return nil, err
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed (status %d): %s", httpResp.StatusCode, string(body))
	}

	var resp RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

func createHTTPClient() (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !sslVerify,
	}

	if caCert != "" {
		caCertData, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func writeConfigFile(resp *RegisterResponse) error {
	configTemplate := `[server]
url = {{ .URL }}
id = {{ .ID }}
key = {{ .Key }}

[ssl]
verify = {{ .Verify }}
{{- if .CACert }}
ca_cert = {{ .CACert }}
{{- end }}

[logging]
debug = false
`
	// Create directory
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Remove empty config file left by systemd-tmpfiles if present
	if info, err := os.Stat(configPath); err == nil && info.Size() == 0 {
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove empty config file: %w", err)
		}
	}

	// Create config file (fail if already exists)
	file, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(file, map[string]interface{}{
		"URL":    serverURL,
		"ID":     resp.ID,
		"Key":    resp.Key,
		"Verify": sslVerify,
		"CACert": caCert,
	})
}
