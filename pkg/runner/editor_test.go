package runner

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEditorRequiresGroup(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS ignores the server's group name")
	}
	manager, err := NewCodeServerManager(t.Context(), "account", "")
	assert.EqualError(t, err, "groupname is required")
	assert.Nil(t, manager)
}

func TestEditorDarwinNonRootKeepsCurrentUser(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		t.Skip("macOS editor behavior without root")
	}
	current, err := user.Current()
	require.NoError(t, err)
	cases := []struct{ username, groupname string }{
		{current.Username, "alpacon"},
		{current.Username, "account"},
		{current.Username, ""},
	}
	for _, tc := range cases {
		t.Run(tc.username+"/"+tc.groupname, func(t *testing.T) {
			id, err := lookupUserForCodeServer(tc.username, tc.groupname)
			require.NoError(t, err)
			assert.Equal(t, current.HomeDir, id.homeDir)
			assert.Nil(t, id.procAttr)
		})
	}
}

func TestGetCodeServerArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("code-server runs on unix sockets; Windows paths and environment differ")
	}
	args := getCodeServerArgs("/run/alpamon-editor/session/cs.sock", "/home/editor/.alpamon-editor")
	assert.Equal(t, []string{
		"--config", "/home/editor/.alpamon-editor/config.yaml",
		"--user-data-dir", "/home/editor/.alpamon-editor",
		"--socket", "/run/alpamon-editor/session/cs.sock", "--socket-mode", "600",
		"--idle-timeout-seconds", strconv.Itoa(int(GetCodeServerConfig().IdleTimeout.Seconds())),
	}, args)
	assert.NotContains(t, args, "--bind-addr")
	assert.Equal(t, "none", GetCodeServerConfig().Auth)
}

func TestEditorEnvironmentAllowList(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("code-server runs on unix sockets; Windows paths and environment differ")
	}
	t.Setenv("EDITOR_SYNTHETIC_SECRET", "synthetic-value")
	t.Setenv("PLUGIN_KEY", "synthetic-value")
	t.Setenv("LC_TIME", "C")
	t.Setenv("LANG", "")
	passthrough := []string{"ALL_PROXY", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "TZ"}
	for _, key := range passthrough {
		if strings.Contains(strings.ToUpper(key), "PROXY") && strings.ToUpper(key) != "NO_PROXY" {
			t.Setenv(key, "http://proxy.invalid:3128")
		} else {
			t.Setenv(key, "configured-value")
		}
	}
	for _, xdg := range []bool{false, true} {
		env := GetCodeServerConfig().ToEnv("/home/editor", xdg, "editor")
		allowed := map[string]bool{"HOME": true, "USER": true, "LOGNAME": true, "PATH": true, "LANG": true, "EXTENSIONS_GALLERY": true}
		if xdg {
			allowed["XDG_DATA_HOME"] = true
			allowed["XDG_CONFIG_HOME"] = true
		}
		seen := map[string]bool{}
		for _, entry := range env {
			key, _, _ := strings.Cut(entry, "=")
			assert.True(t, allowed[key] || strings.HasPrefix(key, "LC_") || editorPassthroughEnv(key), "unexpected variable %s", key)
			assert.False(t, seen[key], "duplicate variable %s", key)
			seen[key] = true
		}
		for _, key := range passthrough {
			if strings.Contains(strings.ToUpper(key), "PROXY") && strings.ToUpper(key) != "NO_PROXY" {
				assert.Contains(t, env, key+"=http://proxy.invalid:3128")
			} else {
				assert.Contains(t, env, key+"=configured-value")
			}
		}
		path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		if runtime.GOOS == "darwin" {
			path += ":/opt/homebrew/bin:/opt/homebrew/sbin"
		}
		assert.Contains(t, env, "PATH="+path)
		assert.NotContains(t, env, "SHELL=/bin/sh")
		assert.Contains(t, env, "USER=editor")
		assert.Contains(t, env, "LOGNAME=editor")
		assert.Contains(t, env, "HOME=/home/editor")
		assert.Contains(t, env, "LC_TIME=C")
		assert.Contains(t, env, "LANG=C.UTF-8")
	}
}

func TestIsCodeServerInstalled(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Result depends on whether code-server is installed on the system
	result := isCodeServerInstalled()
	assert.IsType(t, true, result, "Should return a boolean")
}

func TestGetCodeServerPath(t *testing.T) {
	// This test verifies function behavior
	// If code-server is installed, it should return a path
	// If not, it should return an error
	path, err := getCodeServerPath()
	if isCodeServerInstalled() {
		assert.NoError(t, err, "Should not error when code-server is installed")
		assert.NotEmpty(t, path, "Path should not be empty when code-server is installed")
	} else {
		assert.Error(t, err, "Should error when code-server is not installed")
	}
}

// TestValidateUserDataDirNameRejectsUnsafeNames covers the precondition the
// O_NOFOLLOW helpers rely on: the name must be one usable path component. The
// check is exercised directly rather than through the config singleton, which
// a test may not mutate once anything in this package runs in parallel.
func TestValidateUserDataDirNameRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", filepath.Join("..", "escape"), filepath.Join(".config", "editor")} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorContains(t, validateUserDataDirName(name), "invalid user data dir name")
		})
	}
}

// TestValidateUserDataDirNameAcceptsAPlainComponent guards the other side: a
// leading dot or a doubled one is an ordinary name, and rejecting it would
// take the shipped default down with it.
func TestValidateUserDataDirNameAcceptsAPlainComponent(t *testing.T) {
	for _, name := range []string{".alpamon-editor", "..foo", "editor"} {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, validateUserDataDirName(name))
		})
	}
}

// TestToSettingsJSONGolden locks the settings.json wire format so future
// edits to codeServerSettings can't silently change the emitted output.
func TestToSettingsJSONGolden(t *testing.T) {
	c := &CodeServerConfig{
		ColorTheme:                "Default Dark Modern",
		StartupEditor:             "none",
		RestoreWindows:            "none",
		WindowTitle:               "Alpamon Editor",
		TelemetryLevel:            "off",
		UpdateMode:                "none",
		DisableWorkspaceTrust:     true,
		DisableWelcomeWalkthrough: true,
	}
	want := `{
  "workbench.colorTheme": "Default Dark Modern",
  "window.title": "Alpamon Editor",
  "telemetry.telemetryLevel": "off",
  "workbench.startupEditor": "none",
  "window.restoreWindows": "none",
  "update.mode": "none",
  "security.workspace.trust.enabled": false,
  "workbench.welcomePage.walkthroughs.openOnInstall": false
}`
	got, err := c.ToSettingsJSON()
	assert.NoError(t, err)
	assert.Equal(t, want, string(got))
}

// TestWaitForReadyChecksTheExitBeforeTheDial: another process can replace the socket
// the moment code-server dies, and a dial that answers is then not our server.
func TestWaitForReadyChecksTheExitBeforeTheDial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix editor socket")
	}
	dir, err := os.MkdirTemp("", "editor-exit-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "cs.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer ln.Close()
	m := &CodeServerManager{ctx: t.Context(), socketPath: socket}

	waitDone := make(chan struct{})
	close(waitDone)

	assert.ErrorContains(t, m.waitForReady(waitDone), "exited unexpectedly")
}

func TestCodeServerInstallArgs(t *testing.T) {
	cases := []struct {
		name   string
		goos   string
		isRoot bool
		want   []string
	}{
		{"root macOS installs standalone under its own prefix", "darwin", true, []string{"-s", "--", "--method", "standalone", "--prefix", "/opt/alpamon/code-server"}},
		{"non-root macOS keeps the script defaults", "darwin", false, nil},
		{"root Linux keeps the package manager install", "linux", true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := codeServerInstallArgs(tc.goos, tc.isRoot)

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEditorSocketBasePaths(t *testing.T) {
	assert.Equal(t, "/run/alpamon-editor", editorSocketBase("linux", 0, "/run/alpamon"))
	assert.Equal(t, "/var/run/alpamon-editor", editorSocketBase("darwin", 0, "/var/run/alpamon"))
	assert.Equal(t, filepath.Join("/tmp/alpamon", "editor"), editorSocketBase("linux", 1000, "/tmp/alpamon"))
}

func TestEditorProxyCredentialNotInherited(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Run(key, func(t *testing.T) {
			for _, value := range []string{"http://review:synthetic-proxy-secret@proxy.invalid:3128", "http://review@proxy.invalid:3128", "http://proxy.invalid:3128", "://bad", "proxy.invalid:3128", "proxy:3128", "10.0.0.1:3128", "http://user:1234/x@proxy:8080", "http://user:1234?x@proxy:8080", "http://user:1234#x@proxy:8080", "http:///missing", "http://%zz"} {
				t.Setenv(key, value)
				env := GetCodeServerConfig().ToEnv("/home/review", false, "review")
				if value == "proxy:3128" || value == "10.0.0.1:3128" {
					assert.Contains(t, env, key+"=http://"+value)
				} else if strings.Contains(value, "proxy.invalid:3128") {
					assert.Contains(t, env, key+"=http://proxy.invalid:3128")
				} else {
					for _, entry := range env {
						assert.False(t, strings.HasPrefix(entry, key+"="))
					}
				}
				assert.NotContains(t, strings.Join(env, "\n"), "synthetic-proxy-secret")
				assert.NotContains(t, strings.Join(env, "\n"), "review@proxy.invalid")
			}
		})
	}
}

func TestEditorNonRootRefusesAnotherAccount(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("non-root agent behavior")
	}
	current, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	require.NoError(t, err)
	other := "root"
	require.NotEqual(t, other, current.Username)
	id, err := lookupUserForCodeServer(other, "root")
	assert.ErrorContains(t, err, "agent must run as the requested account or root")
	assert.Nil(t, id)
}
