package runner

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindAvailablePort(t *testing.T) {
	port, err := findAvailablePort()
	assert.NoError(t, err, "Failed to find available port")
	assert.True(t, port > 0, "Port should be greater than 0")
	assert.True(t, port <= 65535, "Port should be less than or equal to 65535")
}

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
		{"nobody", "nogroup"}, // another account still runs as the current user
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

func TestFindAvailablePortRepeated(t *testing.T) {
	for range 10 {
		port, err := findAvailablePort()
		assert.NoError(t, err, "Failed to find available port")
		assert.True(t, port > 0 && port <= 65535, "Port should be in valid range")
	}
}

func TestGetCodeServerArgs(t *testing.T) {
	userDataDir := "/tmp/test-user-data"
	args := getCodeServerArgs(8080, userDataDir)

	assert.Contains(t, args, "--config", "Args should contain --config")
	assert.Contains(t, args, "--user-data-dir", "Args should contain --user-data-dir")
	assert.Contains(t, args, userDataDir, "Args should contain user data dir path")
	assert.Contains(t, args, "--bind-addr", "Args should contain --bind-addr")
	assert.Contains(t, args, "127.0.0.1:8080", "Bind address should be 127.0.0.1:8080")
	assert.Contains(t, args, "--idle-timeout-seconds", "Args should contain --idle-timeout-seconds")
}

func TestGetCodeServerArgsDifferentPorts(t *testing.T) {
	userDataDir := "/tmp/test-user-data"
	testCases := []struct {
		port     int
		expected string
	}{
		{8080, "127.0.0.1:8080"},
		{3000, "127.0.0.1:3000"},
		{65535, "127.0.0.1:65535"},
	}

	for _, tc := range testCases {
		args := getCodeServerArgs(tc.port, userDataDir)
		assert.Contains(t, args, tc.expected, "Bind address should match port")
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

// TestWaitForReadyChecksTheExitBeforeTheDial: another process can grab the port
// the moment code-server dies, and a dial that answers is then not our server.
func TestWaitForReadyChecksTheExitBeforeTheDial(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	m := &CodeServerManager{}
	m.port, err = strconv.Atoi(port)
	require.NoError(t, err)

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
