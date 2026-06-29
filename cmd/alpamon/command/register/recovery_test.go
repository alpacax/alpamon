package register

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/cloud"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRegisterServer is the common Alpacon mock for these tests: it answers the
// register POST with a 201 + {newID}, and records the id of every unregister
// DELETE into deletedIDs (nil to ignore).
func mockRegisterServer(newID string, deletedIDs *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(RegisterResponse{ID: newID, Key: newID + "-key", Name: "test-server"})
		case http.MethodDelete:
			if deletedIDs != nil {
				*deletedIDs = append(*deletedIDs, parseUnregisterID(r.URL.Path))
			}
			w.WriteHeader(http.StatusOK)
		}
	}
}

// withRecoveryTestEnv points the package globals at a mock Alpacon server and a
// temp config path, and stubs the side-effecting seams (dirs/service) to no-ops
// so registration logic can be exercised hermetically — without touching the
// real filesystem, OS service manager, or network. All globals are restored on
// cleanup. Returns the temp config path.
func withRecoveryTestEnv(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cfg := filepath.Join(t.TempDir(), "alpamon.conf")

	// Snapshot everything we mutate.
	var (
		oURL, oToken, oName, oPlat, oCA, oCfg = serverURL, apiToken, serverName, platform, caCert, configPath
		oSSL, oForce, oNoRB, oNCP             = sslVerify, force, noRollback, noCloudProbe
		oTags                                 = tags
		oDetect                               = detectCloud
		oEnsure                               = ensureInstalledFn
		oWrite, oDirs, oStart, oStop, oRemove = writeConfigFileFn, ensureDirectoriesFn, startServiceFn, stopServiceFn, removeServiceFn
		oUSSL, oUCA, oUYes, oUKeep            = unregisterSSLVerify, unregisterCaCert, unregisterYes, unregisterKeepConfig
	)
	t.Cleanup(func() {
		serverURL, apiToken, serverName, platform, caCert, configPath = oURL, oToken, oName, oPlat, oCA, oCfg
		sslVerify, force, noRollback, noCloudProbe = oSSL, oForce, oNoRB, oNCP
		tags = oTags
		detectCloud = oDetect
		ensureInstalledFn = oEnsure
		writeConfigFileFn, ensureDirectoriesFn, startServiceFn, stopServiceFn, removeServiceFn = oWrite, oDirs, oStart, oStop, oRemove
		unregisterSSLVerify, unregisterCaCert, unregisterYes, unregisterKeepConfig = oUSSL, oUCA, oUYes, oUKeep
	})

	serverURL = server.URL
	apiToken = "test-token"
	serverName = "test-server"
	platform = "debian"
	caCert = ""
	sslVerify = true
	force = false
	noRollback = false
	noCloudProbe = true // keep detectCloudTags from touching the network
	tags = nil
	configPath = cfg
	detectCloud = func(context.Context) (*cloud.Metadata, error) { return nil, cloud.ErrNoCloudProvider }

	// Production config writer (writes to the temp configPath), no-op everything
	// that would touch the OS. Individual tests override as needed.
	// ensureInstalled is a no-op on Unix but copies the binary + re-execs +
	// os.Exit on Windows, so it MUST be stubbed for hermetic, cross-platform tests.
	ensureInstalledFn = func() (bool, error) { return false, nil }
	writeConfigFileFn = writeConfigFile
	ensureDirectoriesFn = func() error { return nil }
	startServiceFn = func() error { return nil }
	stopServiceFn = func() error { return nil }
	removeServiceFn = func() error { return nil }

	unregisterSSLVerify = true
	unregisterCaCert = ""
	unregisterYes = true
	unregisterKeepConfig = false

	return cfg
}

func testCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetContext(context.Background())
	return c
}

func parseUnregisterID(p string) string {
	p = strings.TrimSuffix(p, "/")
	p = strings.TrimSuffix(p, "/unregister")
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

func writeConf(t *testing.T, path, url, id, key string) {
	t.Helper()
	body := "[server]\nurl = " + url + "\nid = " + id + "\nkey = " + key + "\n\n[ssl]\nverify = true\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// --- Within-run rollback ------------------------------------------------------

func TestRunRegister_RollbackUnregistersOnConfigWriteFailure(t *testing.T) {
	var deletedIDs []string
	cfg := withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))

	// Fault the config write: the remote record exists by then, so the deferred
	// rollback must best-effort unregister it.
	writeConfigFileFn = func(*RegisterResponse) error { return errors.New("disk full") }

	err := runRegister(testCmd(), nil)
	require.Error(t, err)
	assert.Contains(t, deletedIDs, "new-id", "rollback must DELETE the just-created remote record")
	_, statErr := os.Stat(cfg)
	assert.True(t, os.IsNotExist(statErr), "no config should be left behind")
}

func TestRunRegister_NoRollbackLeavesRemoteRecord(t *testing.T) {
	var deletedIDs []string
	withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))
	noRollback = true
	writeConfigFileFn = func(*RegisterResponse) error { return errors.New("disk full") }

	err := runRegister(testCmd(), nil)
	require.Error(t, err)
	assert.Empty(t, deletedIDs, "--no-rollback must not issue a compensating DELETE")
}

func TestRunRegister_ServiceStartFailureDoesNotRollback(t *testing.T) {
	var deletedIDs []string
	cfg := withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))
	startServiceFn = func() error { return errors.New("service start failed") }

	err := runRegister(testCmd(), nil)
	require.NoError(t, err, "a best-effort service-start failure is non-fatal")
	assert.Empty(t, deletedIDs, "service-start failure must not trigger rollback")
	_, statErr := os.Stat(cfg)
	assert.NoError(t, statErr, "config must persist when registration committed")
}

// --- register --force ---------------------------------------------------------

func TestRunRegister_ForceRetiresOldRegistrationAfterNewSucceeds(t *testing.T) {
	var deletedIDs []string
	cfg := withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))
	writeConf(t, cfg, serverURL, "old-id", "old-key")
	force = true
	var stopCalled bool
	stopServiceFn = func() error { stopCalled = true; return nil }

	err := runRegister(testCmd(), nil)
	require.NoError(t, err)
	assert.Contains(t, deletedIDs, "old-id", "old remote record must be unregistered after the new one succeeds")
	assert.NotContains(t, deletedIDs, "new-id", "the new record must not be unregistered on success")
	assert.True(t, stopCalled, "previous service must be stopped before the fresh start")

	data, readErr := os.ReadFile(cfg)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "id = new-id", "config must be rewritten with the new identity")
}

func TestRunRegister_ForceStopsServiceEvenWhenPriorConfigUnreadable(t *testing.T) {
	var deletedIDs []string
	cfg := withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))
	// Corrupt config: config.ReadServer fails (priorReg stays nil) — the core
	// stuck-after-failed-register case. A leftover service must still be stopped.
	require.NoError(t, os.WriteFile(cfg, []byte("garbage, no [server] section\n"), 0o600))
	force = true
	var stopCalled bool
	stopServiceFn = func() error { stopCalled = true; return nil }

	err := runRegister(testCmd(), nil)
	require.NoError(t, err)
	assert.True(t, stopCalled, "stopService must run under --force even when the prior config is unreadable")
	assert.Empty(t, deletedIDs, "with an unreadable prior config there is no old id/key to unregister")

	data, readErr := os.ReadFile(cfg)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "id = new-id", "corrupt config must be replaced with the new identity")
}

// finding #1: a write failure under --force must NOT lose the existing config.
func TestRunRegister_ForceKeepsOldConfigWhenWriteFails(t *testing.T) {
	var deletedIDs []string
	cfg := withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))
	writeConf(t, cfg, serverURL, "old-id", "old-key")
	force = true
	writeConfigFileFn = func(*RegisterResponse) error { return errors.New("disk full") }

	err := runRegister(testCmd(), nil)
	require.Error(t, err)
	assert.Contains(t, deletedIDs, "new-id", "the just-created record must be rolled back")
	assert.NotContains(t, deletedIDs, "old-id", "the old record must be left intact (its teardown never runs)")

	data, readErr := os.ReadFile(cfg)
	require.NoError(t, readErr, "the existing config must NOT be lost on a write failure")
	assert.Contains(t, string(data), "id = old-id")
}

// --force must fail fast (before the POST) when an existing config is present
// but unreadable, rather than overwriting it with no way to restore on rollback.
func TestRunRegister_ForceFailsFastWhenExistingConfigUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0000 does not block reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	var posted bool
	cfg := withRecoveryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posted = true
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegisterResponse{ID: "new-id", Key: "new-key", Name: "test-server"})
	})
	writeConf(t, cfg, serverURL, "old-id", "old-key")
	require.NoError(t, os.Chmod(cfg, 0o000))
	t.Cleanup(func() { _ = os.Chmod(cfg, 0o600) })
	force = true

	err := runRegister(testCmd(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read existing config")
	assert.False(t, posted, "must fail fast before creating a new remote record")

	// The existing config must be left untouched.
	require.NoError(t, os.Chmod(cfg, 0o600))
	data, readErr := os.ReadFile(cfg)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "id = old-id")
}

// finding #1: a post-write failure under --force must RESTORE the prior config.
func TestRunRegister_ForceRestoresOldConfigWhenDirSetupFails(t *testing.T) {
	var deletedIDs []string
	cfg := withRecoveryTestEnv(t, mockRegisterServer("new-id", &deletedIDs))
	writeConf(t, cfg, serverURL, "old-id", "old-key")
	force = true
	// writeConfigFile (real) succeeds and replaces the config with new-id; the
	// next step then fails, so the rollback must restore the old config.
	ensureDirectoriesFn = func() error { return errors.New("mkdir failed") }

	err := runRegister(testCmd(), nil)
	require.Error(t, err)
	assert.Contains(t, deletedIDs, "new-id", "the just-created record must be rolled back")
	assert.NotContains(t, deletedIDs, "old-id", "the old record must be left intact")

	data, readErr := os.ReadFile(cfg)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "id = old-id", "the prior config must be restored on rollback")
}

func TestRunRegister_ForceDoesNotTearDownOldWhenNewRegistrationFails(t *testing.T) {
	var deleted bool
	cfg := withRecoveryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// New registration rejected (e.g. invalid/expired token).
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"detail":"invalid token"}`))
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusOK)
		}
	})
	writeConf(t, cfg, serverURL, "old-id", "old-key")
	force = true

	err := runRegister(testCmd(), nil)
	require.Error(t, err, "a rejected registration must surface as an error")
	assert.False(t, deleted, "the existing registration must NOT be unregistered when the new POST fails")

	data, readErr := os.ReadFile(cfg)
	require.NoError(t, readErr, "the existing config must be left intact")
	assert.Contains(t, string(data), "id = old-id")
}

// --- unregister ---------------------------------------------------------------

func TestRunUnregister_DeletesRemoteServiceAndConfig(t *testing.T) {
	var deleted bool
	var auth string
	cfg := withRecoveryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
			auth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		}
	})
	writeConf(t, cfg, serverURL, "srv-1", "key-1")
	var removeCalled bool
	removeServiceFn = func() error { removeCalled = true; return nil }

	err := runUnregister(testCmd(), nil)
	require.NoError(t, err)
	assert.True(t, deleted, "unregister must DELETE the remote record")
	assert.Contains(t, auth, `id="srv-1"`, "unregister must authenticate with the server id/key")
	assert.True(t, removeCalled, "unregister must remove the OS service")
	_, statErr := os.Stat(cfg)
	assert.True(t, os.IsNotExist(statErr), "unregister must remove the config")
}

func TestRunUnregister_NoConfigIsNoop(t *testing.T) {
	var deleted bool
	withRecoveryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
		}
		w.WriteHeader(http.StatusOK)
	})
	// configPath points at a temp file that does not exist.
	err := runUnregister(testCmd(), nil)
	require.NoError(t, err, "unregister on a clean box is a no-op")
	assert.False(t, deleted)
}

func TestRunUnregister_KeepConfigPreservesConfig(t *testing.T) {
	var deleted bool
	cfg := withRecoveryTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
		}
		w.WriteHeader(http.StatusOK)
	})
	writeConf(t, cfg, serverURL, "srv-1", "key-1")
	unregisterKeepConfig = true

	err := runUnregister(testCmd(), nil)
	require.NoError(t, err)
	assert.True(t, deleted)
	_, statErr := os.Stat(cfg)
	assert.NoError(t, statErr, "--keep-config must leave the config in place")
}

// --- confirm / flags / removeService -----------------------------------------

func TestConfirm(t *testing.T) {
	cases := map[string]bool{
		"y\n":    true,
		"Y\n":    true,
		"yes\n":  true,
		"YES\n":  true,
		" y \n":  true,
		"n\n":    false,
		"\n":     false,
		"nope\n": false,
		"":       false, // EOF / empty stdin → abort
	}
	for in, want := range cases {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		_, _ = w.WriteString(in)
		_ = w.Close()

		old := os.Stdin
		os.Stdin = r
		got := confirm("proceed?")
		os.Stdin = old
		_ = r.Close()

		assert.Equalf(t, want, got, "confirm(%q)", in)
	}
}

func TestRecoveryFlagsRegistered(t *testing.T) {
	assert.NotNil(t, RegisterCmd.Flags().Lookup("force"))
	assert.NotNil(t, RegisterCmd.Flags().Lookup("no-rollback"))
	assert.NotNil(t, UnregisterCmd.Flags().Lookup("yes"))
	assert.NotNil(t, UnregisterCmd.Flags().Lookup("keep-config"))
	assert.NotNil(t, UnregisterCmd.Flags().Lookup("ssl-verify"))
	assert.NotNil(t, UnregisterCmd.Flags().Lookup("ca-cert"))
}

// TestRemoveService_Idempotent exercises the real per-OS removeService against
// the live service manager. It is gated behind ALPAMON_TEST_SERVICE because it
// would stop/delete a real alpamon service if one is installed on the host;
// run with ALPAMON_TEST_SERVICE=1 on a throwaway box. On a clean box it must be
// a no-op that returns nil.
func TestRemoveService_Idempotent(t *testing.T) {
	if os.Getenv("ALPAMON_TEST_SERVICE") != "1" {
		t.Skip("set ALPAMON_TEST_SERVICE=1 to run (touches the real OS service manager)")
	}
	assert.NoError(t, removeService())
}
