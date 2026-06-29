// Package migrate implements the `alpamon migrate` subcommand: move this
// agent from its current Alpacon workspace to a different one without
// requiring any back-channel access (SSH, console, etc.) — the only
// channel available is assumed to be the existing alpacon Websh session.
//
// User flow:
//
//  1. Operator creates a registration token in workspace B.
//  2. Operator opens Websh on the agent's current workspace (A) and runs:
//     sudo alpamon migrate --url https://b... --token <REGISTRATION_TOKEN>
//  3. The command registers on B, atomically swaps /etc/alpamon/alpamon.conf,
//     writes a marker file, schedules a systemd-run timer to restart
//     alpamon ~30s later, and returns. The Websh session disconnects as
//     soon as the restart fires.
//  4. Agent comes back up pointing at B. On first successful WebSocket
//     auth handshake, the marker is cleared and the backup is deleted.
//  5. If B never accepts the agent, the in-agent watchdog rolls back to A
//     after --rollback-timeout and the operator sees the server reappear
//     on workspace A.
//
// See pkg/migrate for the durable-state ordering rules and watchdog logic.
package migrate

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
	"regexp"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/migrate"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

// restartDelay is how long systemd waits after the command returns before
// kicking the alpamon service. Tuned generously so that:
//   - the user has time to read the success message before disconnect;
//   - the migrate process itself has comfortably exited before systemd
//     restarts the service — `systemctl restart alpamon` kills the entire
//     alpamon.service cgroup (default KillMode=control-group), and Websh
//     launched migrate as a descendant of that cgroup, so a too-short
//     delay can SIGTERM the migrate process mid-print and leave the
//     operator with no confirmation of what committed.
const restartDelay = 30 * time.Second

var (
	newURL          string
	apiToken        string
	serverName      string
	platform        string
	sslVerify       bool
	caCert          string
	rollbackTimeout time.Duration
	force           bool
)

// Cmd is the migrate subcommand exported for registration in root.go.
var Cmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate this server from its current workspace to another",
	Long: `Migrate this server to a different Alpacon workspace.

Reads the current /etc/alpamon/alpamon.conf, registers on the target
workspace with the provided token, atomically swaps the config, and
schedules a self-restart so the agent reconnects to the new workspace.

If the agent fails to establish a WebSocket connection to the new
workspace within --rollback-timeout, the previous configuration is
restored automatically and the server reappears on the original
workspace. No SSH or external access is required.

Run this from a Websh session on the current workspace. Your session
will disconnect once the restart fires; reconnect from the new
workspace to verify the agent is online.

Example:
  sudo alpamon migrate \
    --url https://workspace-b.alpacon.example.com \
    --token <REGISTRATION_TOKEN>`,
	RunE: runMigrate,
}

func init() {
	Cmd.Flags().StringVar(&newURL, "url", "", "Target Alpacon workspace URL (required)")
	Cmd.Flags().StringVar(&apiToken, "token", "", "Registration token issued by the target workspace (required)")
	Cmd.Flags().StringVar(&serverName, "name", "", "Server name (optional, defaults to hostname)")
	Cmd.Flags().StringVar(&platform, "platform", "", "Platform (debian/rhel/darwin/windows, auto-detected when omitted)")
	Cmd.Flags().BoolVar(&sslVerify, "ssl-verify", true, "SSL certificate verification")
	Cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path")
	Cmd.Flags().DurationVar(&rollbackTimeout, "rollback-timeout", migrate.DefaultRollbackTimeout,
		"Auto-rollback if the new workspace is not reachable within this window")
	Cmd.Flags().BoolVar(&force, "force", false,
		"Proceed even if a previous migration is still pending (use with care)")

	_ = Cmd.MarkFlagRequired("url")
	_ = Cmd.MarkFlagRequired("token")
}

func runMigrate(cmd *cobra.Command, _ []string) error {
	if !utils.HasSystemd() {
		return errors.New(
			"alpamon migrate currently requires systemd: the watchdog and self-restart rely on it")
	}

	configPath := filepath.Join(utils.ConfigDir(), "alpamon.conf")

	if rollbackTimeout > migrate.MaxRollbackTimeout {
		return fmt.Errorf("--rollback-timeout %s exceeds maximum of %s", rollbackTimeout, migrate.MaxRollbackTimeout)
	}
	if rollbackTimeout < 30*time.Second {
		return fmt.Errorf("--rollback-timeout %s is too short; minimum 30s", rollbackTimeout)
	}

	if pending, err := migrate.LoadPending(); err != nil {
		return fmt.Errorf("inspect migration state: %w", err)
	} else if pending != nil && !force {
		return fmt.Errorf(
			"a previous migration is still pending (marker at %s, expires %s)\n"+
				"wait for the watchdog to settle or pass --force to override",
			migrate.MarkerPath(), pending.ExpiresAt.Format(time.RFC3339))
	}

	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("active config not found at %s: %w", configPath, err)
	}

	if platform == "" {
		platform = detectPlatform()
	}

	current, err := readCurrentServer(configPath)
	if err != nil {
		return fmt.Errorf("read current server from conf: %w", err)
	}
	if normalizeURL(current.URL) == normalizeURL(newURL) {
		return fmt.Errorf("already pointed at %s; nothing to migrate", current.URL)
	}
	oldURL := current.URL

	// Pick the server name in this priority order:
	//   1. --name <X>             (operator override; honored as-is)
	//   2. A's display name minus suffix
	//      (preserves any rename the operator did via the console;
	//       hostname can be stale or generic like `ip-172-31-...`)
	//   3. local hostname         (last resort if A's API is unreachable)
	if serverName == "" {
		fetchCtx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
		got, ferr := fetchCurrentName(fetchCtx, current)
		cancel()
		switch {
		case ferr != nil:
			log.Warn().Err(ferr).Msg("Could not fetch current server name from source workspace; falling back to hostname.")
		case strings.TrimSpace(got) == "":
			log.Warn().Msg("Source workspace returned an empty name; falling back to hostname.")
		default:
			serverName = stripGeneratedSuffix(got)
			fmt.Printf("Using current workspace name as prefix: %s\n", serverName)
		}
	}
	if serverName == "" {
		hn, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("read hostname: %w", err)
		}
		serverName = normalizeHostname(hn)
	}

	fmt.Printf("Registering on %s ...\n", newURL)
	resp, err := registerOnTarget(cmd.Context())
	if err != nil {
		return fmt.Errorf("registration on target workspace failed: %w", err)
	}
	fmt.Printf("  -> registered as %s (id=%s)\n", resp.Name, resp.ID)

	// Commit durable state in a strict order so a crash at any step is
	// recoverable by the next startup's watchdog. See pkg/migrate for the
	// full state-ordering contract.
	backupPath, err := migrate.BackupConf(configPath)
	if err != nil {
		cleanupTargetRegistration(resp.ID, resp.Key)
		return fmt.Errorf("back up current config: %w", err)
	}
	fmt.Printf("  -> backed up to %s\n", backupPath)

	state := &migrate.PendingState{
		BackupConfPath: backupPath,
		OldURL:         oldURL,
		NewURL:         newURL,
		NewServerID:    resp.ID,
		NewServerKey:   resp.Key,
		StartedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(rollbackTimeout),
	}
	if err := migrate.WritePending(state); err != nil {
		cleanupTargetRegistration(resp.ID, resp.Key)
		_ = os.Remove(backupPath)
		return fmt.Errorf("write migration marker: %w", err)
	}

	newConf, err := buildConfContent(newURL, resp.ID, resp.Key, sslVerify, caCert)
	if err != nil {
		cleanupTargetRegistration(resp.ID, resp.Key)
		_ = migrate.ClearPending()
		_ = os.Remove(backupPath)
		return fmt.Errorf("build new conf: %w", err)
	}
	if err := migrate.WriteConfAtomic(configPath, []byte(newConf), 0600); err != nil {
		cleanupTargetRegistration(resp.ID, resp.Key)
		_ = migrate.ClearPending()
		_ = os.Remove(backupPath)
		return fmt.Errorf("write new config: %w", err)
	}

	if err := migrate.ScheduleSelfRestart(restartDelay); err != nil {
		// We're not committed yet from the agent's perspective — it still
		// has the old config in memory. Roll back synchronously so the
		// operator can re-run cleanly.
		_ = migrate.RestoreBackup(backupPath, configPath)
		_ = migrate.ClearPending()
		cleanupTargetRegistration(resp.ID, resp.Key)
		_ = os.Remove(backupPath)
		return fmt.Errorf("schedule restart: %w", err)
	}

	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Migration scheduled")
	fmt.Println("==========================================")
	fmt.Printf("  From: %s\n", oldURL)
	fmt.Printf("  To:   %s\n", newURL)
	fmt.Printf("  ID:   %s\n", resp.ID)
	fmt.Printf("  Restart in: %s\n", restartDelay)
	fmt.Printf("  Auto-rollback if not connected within: %s\n", rollbackTimeout)
	fmt.Println("==========================================")
	fmt.Println("Your current session will disconnect shortly.")
	fmt.Printf("Reconnect from %s to verify the agent is online.\n", newURL)
	fmt.Println("If the agent reappears on the original workspace, migration failed and was auto-rolled-back.")
	return nil
}

// currentServer is what we need from the active alpamon.conf to (a) know
// what workspace we're migrating away from and (b) authenticate to that
// workspace's API to look up our display name.
type currentServer struct {
	URL string
	ID  string
	Key string
}

// readCurrentServer parses the conf as INI and returns the [server]
// section's url/id/key. config.LoadConfig is unsuitable here because it
// log.Fatal()s on any validation problem; we want a graceful error path.
func readCurrentServer(path string) (*currentServer, error) {
	f, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("parse conf: %w", err)
	}
	section, err := f.GetSection("server")
	if err != nil {
		return nil, errors.New("[server] section missing")
	}
	get := func(name string) string {
		k, err := section.GetKey(name)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(k.String())
	}
	sc := &currentServer{URL: get("url"), ID: get("id"), Key: get("key")}
	if sc.URL == "" {
		return nil, errors.New("url not found in [server] section")
	}
	if sc.ID == "" || sc.Key == "" {
		return nil, errors.New("id/key not found in [server] section")
	}
	return sc, nil
}

// generatedSuffixRE matches the 6-hex-char suffix that
// servers/api/serializers.py:ServerRegisterSerializer.create appends to
// every registered server name. We strip it before reusing the operator-
// facing prefix on the target workspace so the new server doesn't end up
// with two stacked suffixes (`mybox-abc123-xyz789`).
var generatedSuffixRE = regexp.MustCompile(`-[0-9a-f]{6}$`)

func stripGeneratedSuffix(name string) string {
	return generatedSuffixRE.ReplaceAllString(name, "")
}

// fetchCurrentName queries the source workspace for this server's
// human-assigned name (which the operator may have edited via the
// Alpacon console — that edit isn't reflected in `hostname`). The agent
// authenticates as itself via the standard `id="...", key="..."` scheme
// already used by alpamon's session layer.
//
// On any failure (network, auth, 404), returns "" with a non-nil error
// so the caller can fall back to hostname.
func fetchCurrentName(ctx context.Context, sc *currentServer) (string, error) {
	url := fmt.Sprintf("%s/api/servers/servers/%s/",
		strings.TrimSuffix(sc.URL, "/"), sc.ID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf(`id="%s", key="%s"`, sc.ID, sc.Key))

	client, err := buildHTTPClient(sslVerify, caCert)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var data struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return data.Name, nil
}

func normalizeURL(u string) string {
	return strings.TrimSuffix(strings.TrimSpace(u), "/")
}

func buildConfContent(url, id, key string, verify bool, caCertPath string) (string, error) {
	tpl := `[server]
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
	t, err := template.New("conf").Parse(tpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]any{
		"URL":    url,
		"ID":     id,
		"Key":    key,
		"Verify": verify,
		"CACert": caCertPath,
	}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// registerRequest mirrors servers/api/serializers.py:ServerRegisterSerializer.
type registerRequest struct {
	Name     string            `json:"name"`
	Platform string            `json:"platform"`
	Tags     map[string]string `json:"tags,omitempty"`
}

type registerResponse struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

func registerOnTarget(ctx context.Context) (*registerResponse, error) {
	body, err := json.Marshal(registerRequest{Name: serverName, Platform: platform})
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/servers/servers/register/", strings.TrimSuffix(newURL, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf(`token="%s"`, apiToken))
	req.Header.Set("Content-Type", "application/json")

	client, err := buildHTTPClient(sslVerify, caCert)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var r registerResponse
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &r, nil
}

// cleanupTargetRegistration drops the just-created server record on the
// target workspace when the migrate command itself errors out before
// reaching ScheduleSelfRestart. The agent-side watchdog has its own copy
// via pkg/migrate.BestEffortUnregister; this thin wrapper exists so the
// migrate command can reach the same helper without surfacing pkg
// internals to subcommand callers.
func cleanupTargetRegistration(id, key string) {
	migrate.BestEffortUnregister(newURL, id, key, sslVerify, caCert)
}

func buildHTTPClient(verify bool, ca string) (*http.Client, error) {
	cfg := &tls.Config{InsecureSkipVerify: !verify}
	if ca != "" {
		data, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid CA certificate")
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}, nil
}

func normalizeHostname(h string) string {
	if i := strings.Index(h, "."); i > 0 {
		return h[:i]
	}
	return h
}

func detectPlatform() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	info, err := host.Info()
	if err != nil {
		return "debian"
	}
	switch info.Platform {
	case "darwin":
		return "darwin"
	case "ubuntu", "debian", "raspbian":
		return "debian"
	case "centos", "rhel", "redhat", "amazon", "amzn", "fedora", "rocky", "oracle", "ol":
		return "rhel"
	}
	p := strings.ToLower(info.Platform)
	switch {
	case strings.Contains(p, "ubuntu"), strings.Contains(p, "debian"):
		return "debian"
	case strings.Contains(p, "centos"), strings.Contains(p, "rhel"),
		strings.Contains(p, "fedora"), strings.Contains(p, "rocky"):
		return "rhel"
	}
	return "debian"
}
