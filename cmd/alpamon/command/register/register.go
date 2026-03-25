package register

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/spf13/cobra"
)

const (
	alpamonBinPath = "/usr/local/bin/alpamon"
	configPath     = "/etc/alpamon/alpamon.conf"
	logPath        = "/var/log/alpamon/alpamon.log"
)

var (
	serverURL  string
	apiToken   string
	serverName string
	platform   string
	sslVerify  bool
	caCert     string
	tags       map[string]string
)

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

Examples:
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN>
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN> --name my-server
  sudo alpamon register --url https://alpacon.example.com --token <TOKEN> --tag env=prod --tag role=web

Options:
  --url         Alpacon server URL (required)
  --token       API token (servers:register scope required)
  --name        Server name (optional, defaults to hostname)
  --platform    Platform (debian/rhel, auto-detect if omitted)
  --ssl-verify  SSL certificate verification (default: true)
  --ca-cert     CA certificate path
  --tag         Server tags in key=value format (repeatable, or comma-separated: "k1=v1,k2=v2")`,
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

	_ = RegisterCmd.MarkFlagRequired("url")
	_ = RegisterCmd.MarkFlagRequired("token")
}

func runRegister(cmd *cobra.Command, args []string) error {
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

	// 4. Create registration request body
	reqBody := RegisterRequest{
		Name:     serverName,
		Platform: platform,
		Tags:     tags,
	}

	fmt.Printf("Registering server: %s\n", serverURL)

	// 5. API call
	resp, err := sendRegisterRequest(reqBody)
	if err != nil {
		return err
	}

	// 6. Create config file
	if err := writeConfigFile(resp); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	// 7. Create required directories
	if err := ensureDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// 8. Start service
	fmt.Println("\nStarting alpamon service...")
	if err := startService(); err != nil {
		fmt.Printf("Warning: Failed to start service: %v\n", err)
		if utils.HasSystemd() {
			fmt.Println("Please start the service manually:")
			fmt.Println("  sudo systemctl start alpamon")
			fmt.Println("  sudo systemctl enable alpamon")
		} else {
			fmt.Println("Please start alpamon manually:")
			fmt.Println("  /usr/local/bin/alpamon")
		}
	}

	// 9. Success message
	fmt.Printf("\n==========================================\n")
	fmt.Printf("Server registered successfully!\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("  Name: %s\n", resp.Name)
	fmt.Printf("  ID:   %s\n", resp.ID)
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("==========================================\n")

	return nil
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

	switch hostInfo.Platform {
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

func ensureDirectories() error {
	if utils.HasSystemd() {
		if output, err := exec.Command("systemd-tmpfiles", "--create", "alpamon.conf").CombinedOutput(); err != nil {
			return fmt.Errorf("tmpfiles creation failed: %w\n%s", err, string(output))
		}
		return nil
	}
	return utils.EnsureDirectories()
}

func startService() error {
	if utils.HasSystemd() {
		if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("daemon-reload failed: %w\n%s", err, string(output))
		}

		if output, err := exec.Command("systemctl", "start", "alpamon.service").CombinedOutput(); err != nil {
			return fmt.Errorf("start failed: %w\n%s", err, string(output))
		}

		if output, err := exec.Command("systemctl", "enable", "alpamon.service").CombinedOutput(); err != nil {
			return fmt.Errorf("enable failed: %w\n%s", err, string(output))
		}

		fmt.Println("Alpamon service started and enabled.")
		return nil
	}

	// On non-Linux platforms (e.g., macOS development), skip auto-start
	if runtime.GOOS != "linux" {
		return nil
	}

	// Start alpamon as a background process (containers without systemd)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", logPath, err)
	}

	cmd := exec.Command(alpamonBinPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("failed to start alpamon process: %w", err)
	}
	// logFile is inherited by the child process; closing here does not affect the child
	_ = logFile.Close()

	pid := cmd.Process.Pid
	// Release OS resources for the detached child process.
	// When the register process exits, the child is reparented to PID 1.
	// In containers without a proper init (no zombie reaping), this could
	// leave zombies. Most container runtimes use tini or --init by default.
	_ = cmd.Process.Release()

	fmt.Printf("Alpamon started (PID: %d).\n", pid)
	fmt.Printf("Logs: %s\n", logPath)
	return nil
}
