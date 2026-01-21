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
	"strings"
	"text/template"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/spf13/cobra"
)

const configPath = "/etc/alpamon/alpamon.conf"

var (
	serverURL  string
	apiToken   string
	serverName string
	platform   string
	sslVerify  bool
	caCert     string
)

// RegisterRequest represents the request body for server registration
type RegisterRequest struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
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

Options:
  --url         Alpacon server URL (required)
  --token       API token (servers:register scope required)
  --name        Server name (optional, defaults to hostname)
  --platform    Platform (debian/rhel, auto-detect if omitted)
  --ssl-verify  SSL certificate verification (default: true)
  --ca-cert     CA certificate path`,
	RunE: runRegister,
}

func init() {
	RegisterCmd.Flags().StringVar(&serverURL, "url", "", "Alpacon server URL (required)")
	RegisterCmd.Flags().StringVar(&apiToken, "token", "", "API token (servers:register scope required)")
	RegisterCmd.Flags().StringVar(&serverName, "name", "", "Server name (optional, defaults to hostname)")
	RegisterCmd.Flags().StringVar(&platform, "platform", "", "Platform (debian/rhel, auto-detect)")
	RegisterCmd.Flags().BoolVar(&sslVerify, "ssl-verify", true, "SSL certificate verification")
	RegisterCmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path")

	_ = RegisterCmd.MarkFlagRequired("url")
	_ = RegisterCmd.MarkFlagRequired("token")
}

func runRegister(cmd *cobra.Command, args []string) error {
	// 1. Check if config file already exists (prevent re-registration)
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists: %s\nServer is already registered. Delete the config file to re-register", configPath)
	}

	// 2. Auto-detect server name from hostname if not provided
	if serverName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		serverName = hostname
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

	// 7. Start systemd service
	fmt.Println("\nStarting alpamon service...")
	if err := startSystemdService(); err != nil {
		fmt.Printf("Warning: Failed to start service: %v\n", err)
		fmt.Println("Please start the service manually:")
		fmt.Println("  sudo systemctl start alpamon")
		fmt.Println("  sudo systemctl enable alpamon")
	}

	// 8. Success message
	fmt.Printf("\n==========================================\n")
	fmt.Printf("Server registered successfully!\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("  Name: %s\n", resp.Name)
	fmt.Printf("  ID:   %s\n", resp.ID)
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("==========================================\n")

	return nil
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

func startSystemdService() error {
	// Reload systemd daemon
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}

	// Start the service
	if err := exec.Command("systemctl", "start", "alpamon.service").Run(); err != nil {
		return fmt.Errorf("start failed: %w", err)
	}

	// Enable the service
	if err := exec.Command("systemctl", "enable", "alpamon.service").Run(); err != nil {
		return fmt.Errorf("enable failed: %w", err)
	}

	fmt.Println("Alpamon service started and enabled.")
	return nil
}
