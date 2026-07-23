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
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/cloud"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/migrate"
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
	force        bool
	noRollback   bool

	// detectCloud is overridable in tests to inject a stub detector. Production
	// uses cloud.Detect with the default provider list.
	detectCloud = func(ctx context.Context) (*cloud.Metadata, error) {
		_, meta, err := cloud.Detect(ctx, cloud.DefaultProviders())
		return meta, err
	}

	// Test seams: indirections over the side-effecting steps so registration
	// logic (within-run rollback, --force ordering) can be exercised without
	// touching the real filesystem, OS service manager, or relying on platform
	// service behavior. They default to the production implementations, mirroring
	// the detectCloud seam above.
	ensureInstalledFn   = ensureInstalled
	writeConfigFileFn   = writeConfigFile
	ensureDirectoriesFn = ensureDirectories
	startServiceFn      = startService
	stopServiceFn       = stopService
	removeServiceFn     = removeService
)

// registerCloudDetectTimeout caps the synchronous cloud probe at register time
// so a non-cloud host (where all probes time out) still finishes registration
// within a reasonable budget.
const registerCloudDetectTimeout = 5 * time.Second

// serverNameMaxLength mirrors the server's SlugField(max_length=64) on the
// register endpoint.
const serverNameMaxLength = 64

// nameSeparatorRe matches any run of characters outside the slug set
// [A-Za-z0-9_]; hyphens are intentionally excluded so existing/duplicate
// hyphens collapse with adjacent separators.
var nameSeparatorRe = regexp.MustCompile(`[^A-Za-z0-9_]+`)

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
  --no-cloud-probe  Skip cloud metadata IMDS probe
  --force           Recover a stuck server: register anew, then retire the previous registration
  --no-rollback     On failure, leave partial state in place instead of cleaning it up (debug)`,
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
	RegisterCmd.Flags().BoolVar(&force, "force", false, "Recover a stuck server: register anew, then retire the previous registration once the new one is committed")
	RegisterCmd.Flags().BoolVar(&noRollback, "no-rollback", false, "On failure, leave partial state in place instead of cleaning it up (for debugging)")

	_ = RegisterCmd.MarkFlagRequired("url")
	_ = RegisterCmd.MarkFlagRequired("token")
}

func runRegister(cmd *cobra.Command, args []string) error {
	// 0. On Windows, place the binary in %ProgramFiles%\alpamon and
	// re-exec from there so the Service Manager entry we're about to
	// create points at a stable path. No-op on Linux/macOS, where
	// apt/brew already handled placement.
	if relaunched, err := ensureInstalledFn(); err != nil {
		return err
	} else if relaunched {
		return nil
	}

	// 0b. With --force, capture the existing registration up front: the parsed
	// [server] block (to retire the old remote record) and the raw config bytes
	// (to restore on rollback). Reading now—before the new POST—is harmless;
	// the actual teardown happens only once we are committed, so an invalid token
	// or unreachable --url aborts before we touch the existing healthy install.
	var priorReg *config.ServerConfig
	var oldConf []byte
	oldConfMode := os.FileMode(0o600)
	oldSSLVerify := true
	var oldCACert string
	if force {
		// Capture the existing config so a later rollback can restore it. If a
		// config is present but unreadable, fail fast: writeConfigFile would
		// atomically replace it and a post-write failure (e.g. dir setup) would
		// then drop it via removeOnRollback, leaving the host with no config and
		// breaking the --force guarantee. oldConf is therefore set iff a prior
		// config existed and was captured (an empty placeholder, size 0, is not).
		// Also capture the prior [ssl] so retiring the old remote record speaks
		// the OLD workspace's TLS, not this invocation's flags.
		if info, statErr := os.Stat(configPath); statErr == nil && info.Size() > 0 {
			b, readErr := os.ReadFile(configPath)
			if readErr != nil {
				return fmt.Errorf("--force: cannot read existing config %s to enable rollback: %w", configPath, readErr)
			}
			oldConf = b
			oldConfMode = info.Mode().Perm()
			if srv, err := config.ReadServer(configPath); err == nil {
				priorReg = srv
			}
			oldSSLVerify, oldCACert = config.ReadSSL(configPath)
		}
	}

	// 1. Reject a re-register when a live config already exists (skipped under
	// --force, which intentionally replaces an existing registration).
	if !force {
		if err := ensureNotAlreadyRegistered(); err != nil {
			return err
		}
	}

	// 2–5. Resolve the server name (hostname fallback + slug normalization),
	// platform, and merged cloud/user tags, and assemble the request body.
	reqBody, err := buildRegisterRequest(cmd)
	if err != nil {
		return err
	}

	fmt.Printf("Registering server: %s\n", serverURL)

	// Within-run rollback: unless --no-rollback, undo state THIS invocation
	// created if a later step fails. Compensations run LIFO (local cleanup
	// first, the single remote DELETE last—matching the saga ordering in
	// pkg/migrate). committed is flipped once the registration is durably
	// usable; after that point a best-effort service-start failure must NOT
	// trigger a rollback (a registered server whose service merely failed to
	// start is recoverable, and tearing it down would be hostile).
	var rollbacks []func() error
	committed := false
	defer func() {
		if committed || noRollback {
			return
		}
		var errs []error
		for _, rollback := range slices.Backward(rollbacks) {
			if e := rollback(); e != nil {
				errs = append(errs, e)
			}
		}
		if e := errors.Join(errs...); e != nil {
			fmt.Printf("Warning: cleanup after the failed registration did not fully complete: %v\n", e)
		}
	}()

	// 6. API call (creates the remote server record).
	resp, err := sendRegisterRequest(reqBody)
	if err != nil {
		return err
	}
	rollbacks = append(rollbacks, func() error {
		migrate.BestEffortUnregister(serverURL, resp.ID, resp.Key, sslVerify, caCert)
		return nil
	})

	// 7. Write the config via atomic replace (temp + rename, see writeConfigFile).
	// Under --force the previous config stays intact until the new one is renamed
	// into place, so a failed write can never leave the host with no config. The
	// rollback compensation restores the previous config under --force, or removes
	// the freshly written one otherwise.
	if err := writeConfigFileFn(resp); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	if force && oldConf != nil {
		rollbacks = append(rollbacks, func() error {
			return migrate.WriteConfAtomic(configPath, oldConf, oldConfMode)
		})
	} else {
		rollbacks = append(rollbacks, func() error { return removeOnRollback(configPath) })
	}

	// 8. Create required directories
	if err := ensureDirectoriesFn(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Registration is durably usable from here (config + dirs written).
	committed = true

	// 8b. --force: now that the new registration is committed, retire the old one.
	if force {
		retirePriorRegistration(priorReg, resp.ID, oldSSLVerify, oldCACert)
	}

	// 9. Start service
	fmt.Println("\nStarting alpamon service...")
	if err := startServiceFn(); err != nil {
		fmt.Printf("Warning: Failed to start service: %v\n", err)
		printManualStartHint()
	}

	// 10. Success message
	printRegisterSuccess(resp)
	return nil
}

// ensureNotAlreadyRegistered fails if a non-empty config already exists, telling
// the operator how to re-register (unregister / --force). A missing config is the
// clean case; an empty config (e.g. left by systemd-tmpfiles) is allowed and will
// be overwritten. A non-not-exist stat error (e.g. permission/ACL) is surfaced
// rather than silently treated as "no config", which would otherwise fail later
// with a less actionable error during the config write.
func ensureNotAlreadyRegistered() error {
	info, err := os.Stat(configPath)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("inspect config %s: %w", configPath, err)
	case info.Size() > 0:
		return fmt.Errorf("config file already exists: %s\n"+
			"this server appears to be already registered; re-register by running "+
			"'alpamon register --force', or 'alpamon unregister' and then 'alpamon register' again",
			configPath)
	}
	fmt.Printf("Note: Empty config file found at %s, will be overwritten\n", configPath)
	return nil
}

// buildRegisterRequest resolves the server name (hostname fallback + slug
// normalization), platform, and merged cloud/user tags, and returns the request
// body to POST. It prints what it auto-detected/normalized. cmd's context is
// passed through so the cloud IMDS probe stays cancelable. User-supplied --tag
// values win over auto-detected cloud tags so an operator can override a
// misdetection.
func buildRegisterRequest(cmd *cobra.Command) (RegisterRequest, error) {
	if serverName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return RegisterRequest{}, fmt.Errorf("failed to get hostname: %w", err)
		}
		serverName = normalizeHostname(hostname)
		fmt.Printf("Server name auto-detected: %s\n", serverName)
	}

	// Normalize to the server's slug rule (^[-a-zA-Z0-9_]+$) for both the --name
	// and hostname paths so registration never fails with {"code":"invalid"}.
	original := serverName
	serverName = normalizeServerName(serverName)
	if serverName == "" {
		return RegisterRequest{}, fmt.Errorf(
			"server name %q is empty after normalization; pass a valid --name "+
				"(allowed characters: A-Z a-z 0-9 _ -)", original)
	}
	if serverName != original {
		fmt.Printf("Server name normalized to %q\n", serverName)
	}

	if platform == "" {
		platform = detectPlatform()
		fmt.Printf("Platform auto-detected: %s\n", platform)
	}

	finalTags := mergeCloudAndUserTags(detectCloudTags(cmd.Context()), tags)

	return RegisterRequest{Name: serverName, Platform: platform, Tags: finalTags}, nil
}

// retirePriorRegistration tears down the registration that --force is replacing,
// AFTER the new one is committed. It stops (not deletes) the previously-running
// service so the fresh start reloads the new config; this runs even when the
// prior config was unreadable, because a leftover service from a failed install
// may still be running with stale credentials (the stuck case --force exists
// for). The remote unregister needs the old id/key, so it is gated on a readable
// prior config, and it uses the OLD config's TLS settings (sslVerify/caCert) so
// it works against a self-signed / private-CA prior workspace.
func retirePriorRegistration(priorReg *config.ServerConfig, newID string, sslVerify bool, caCert string) {
	if priorReg != nil && priorReg.ID != newID {
		fmt.Printf("--force: unregistering previous server record %s ...\n", priorReg.ID)
		migrate.BestEffortUnregister(priorReg.URL, priorReg.ID, priorReg.Key, sslVerify, caCert)
	}
	if err := stopServiceFn(); err != nil {
		fmt.Printf("Warning: failed to stop the previous service: %v\n", err)
	}
}

// printRegisterSuccess prints the post-registration summary banner.
func printRegisterSuccess(resp *RegisterResponse) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("Server registered successfully!\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("  Name: %s\n", resp.Name)
	fmt.Printf("  ID:   %s\n", resp.ID)
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("==========================================\n")
}

// removeOnRollback deletes path, tolerating an already-absent file. Used as a
// within-run rollback compensation for the config written during registration.
func removeOnRollback(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
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
	maps.Copy(out, auto)
	maps.Copy(out, user)
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

// normalizeServerName coerces an arbitrary name into the server's SlugField
// character set (^[-a-zA-Z0-9_]+$, max 64). It replaces every run of
// disallowed characters (spaces, '.', '/', non-ASCII, ...) with a single '-',
// trims leading/trailing '-', and truncates to serverNameMaxLength. May return
// "" — the caller chooses a fallback.
//
// MUST stay in sync with alpacon-server's normalize_server_name; shared test
// vectors live in both repos' plan docs.
func normalizeServerName(value string) string {
	n := nameSeparatorRe.ReplaceAllString(value, "-")
	n = strings.Trim(n, "-")
	if len(n) > serverNameMaxLength {
		n = n[:serverNameMaxLength]
	}
	return strings.TrimRight(n, "-")
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
	content, err := config.RenderConf(
		config.ServerConfig{URL: serverURL, ID: resp.ID, Key: resp.Key},
		sslVerify, caCert,
	)
	if err != nil {
		return err
	}
	// Atomic replace (temp + fsync + rename, creating the dir at 0700): the file
	// is never left half-written, and any existing config (e.g. an empty file
	// from systemd-tmpfiles, or a prior registration under --force) is replaced
	// only at the final rename—so a failed write cannot orphan the host.
	return migrate.WriteConfAtomic(configPath, []byte(content), 0o600)
}
